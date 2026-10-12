"""AKTOOL Core HTTP API, versioned under /api/v1."""

from __future__ import annotations

import hmac
import json
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from core import __version__, firmware, review, sources
from core.db import RELATION_TYPES, FirmwareRecord
from core.db.migrate import upgrade_to_head
from core.db.session import make_engine, make_session_factory
from core.errors import AktoolError
from core.hexbytes import to_hex
from core.importers import ols_json
from core.jsonfactory import JsonFactory
from core.settings import Settings
from core.validators import ContractValidator, check_against_bin
from core.vault import BinVault

LOCAL_ACTOR = "local-user"


class FirmwarePatch(BaseModel):
    software_id: str | None = None
    calibration_id: str | None = None
    ecu_label: str | None = None
    vehicle_brand: str | None = None
    vehicle_model: str | None = None
    ecu_vendor: str | None = None
    ecu_family: str | None = None
    processor: str | None = None
    base_address: int | None = None
    read_tool: str | None = None
    read_method: str | None = None
    notes: str | None = None
    file_role: Literal["original", "modified", "unknown"] | None = None


class RelationIn(BaseModel):
    target_id: int
    relation_type: Literal[RELATION_TYPES]  # type: ignore[valid-type]
    confidence: float = Field(1.0, ge=0, le=1)


class ValidateIn(BaseModel):
    record: dict[str, Any]
    firmware_id: int | None = None


class RecordIn(BaseModel):
    record: dict[str, Any]


class ExportIn(BaseModel):
    record_id: str
    revision: int | None = None


class ReviewIn(BaseModel):
    revision: int = Field(..., ge=1, description="the revision you reviewed; a newer one makes this a stale review")
    note: str | None = None


class EditIn(ReviewIn):
    changes: dict[str, Any]
    approve: bool = True


class ImportIn(BaseModel):
    record: dict[str, Any]
    apply: bool = False


class OlsExportIn(BaseModel):
    record_ids: list[str] = Field(..., min_length=1)
    decimal_comma: bool = True


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.db_url)
    upgrade_to_head(engine)
    session_factory = make_session_factory(engine)
    vault = BinVault(settings.vault_dir, settings.max_bin_bytes)
    contracts = ContractValidator(settings.schema_dir)
    factory = JsonFactory(contracts, vault, settings.data_dir / "exports")

    app = FastAPI(title="AKTOOL Core", version=__version__)
    app.state.settings = settings

    @app.exception_handler(AktoolError)
    async def _aktool_error(_: Request, exc: AktoolError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    def db() -> Session:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    def actor(x_api_key: str | None = Header(default=None)) -> str:
        if settings.mode == "local":
            return LOCAL_ACTOR
        if not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key or ""):
            raise AktoolError("UNAUTHORIZED", "missing or invalid X-API-Key", status_code=401)
        return "api-key-user"

    @app.get("/api/v1/health")
    def health(session: Session = Depends(db)) -> dict[str, Any]:
        session.execute(select(FirmwareRecord.id).limit(1))
        return {"status": "ok", "version": __version__, "mode": settings.mode,
                "vault": str(settings.vault_dir), "schemas": list(contracts._by_category)}

    @app.post("/api/v1/firmware", status_code=201)
    async def upload_firmware(
        file: UploadFile = File(...),
        software_id: str | None = Form(None), calibration_id: str | None = Form(None),
        ecu_label: str | None = Form(None), vehicle_brand: str | None = Form(None),
        vehicle_model: str | None = Form(None), ecu_vendor: str | None = Form(None),
        ecu_family: str | None = Form(None), processor: str | None = Form(None),
        notes: str | None = Form(None),
        file_role: Literal["original", "modified", "unknown"] = Form("unknown"),
        parent_firmware_id: int | None = Form(None),
        session: Session = Depends(db), who: str = Depends(actor),
    ) -> JSONResponse:
        data = await file.read(settings.max_bin_bytes + 1)
        meta = dict(software_id=software_id, calibration_id=calibration_id, ecu_label=ecu_label,
                    vehicle_brand=vehicle_brand, vehicle_model=vehicle_model, ecu_vendor=ecu_vendor,
                    ecu_family=ecu_family, processor=processor, notes=notes, file_role=file_role)
        if parent_firmware_id is not None:
            firmware.get(session, parent_firmware_id)
        rec, created = firmware.ingest(session, vault, data, file.filename or "upload.bin", who, meta)
        if parent_firmware_id is not None:
            firmware.add_relation(session, rec.id, parent_firmware_id, "modified_from", who)
        body = _firmware_out(session, rec)
        body["created"] = created
        return JSONResponse(status_code=201 if created else 200, content=body)

    @app.get("/api/v1/firmware")
    def list_firmware(q: str | None = None, limit: int = Query(50, ge=1, le=500),
                      session: Session = Depends(db), _: str = Depends(actor)) -> list[dict[str, Any]]:
        return [_firmware_out(session, r, with_relations=False) for r in firmware.search(session, q, limit)]

    @app.get("/api/v1/firmware/{firmware_id}")
    def get_firmware(firmware_id: int, session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        return _firmware_out(session, firmware.get(session, firmware_id))

    @app.patch("/api/v1/firmware/{firmware_id}")
    def patch_firmware(firmware_id: int, patch: FirmwarePatch, session: Session = Depends(db),
                       who: str = Depends(actor)) -> dict[str, Any]:
        rec = firmware.update(session, firmware_id, patch.model_dump(exclude_unset=True), who)
        return _firmware_out(session, rec)

    @app.post("/api/v1/firmware/{firmware_id}/relations", status_code=201)
    def add_relation(firmware_id: int, body: RelationIn, session: Session = Depends(db),
                     who: str = Depends(actor)) -> dict[str, Any]:
        rel = firmware.add_relation(session, firmware_id, body.target_id, body.relation_type, who, body.confidence)
        return {"id": rel.id, "source_id": rel.source_id, "target_id": rel.target_id,
                "relation_type": rel.relation_type, "confidence": rel.confidence}

    @app.get("/api/v1/firmware/{firmware_id}/bytes")
    def read_bytes(firmware_id: int, offset: int = Query(..., ge=0), length: int = Query(..., gt=0),
                   session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        rec = firmware.get(session, firmware_id)
        data = vault.read_range(rec.blob.sha256, offset, length, settings.max_range_bytes)
        return {"firmware_id": rec.id, "offset": offset, "offset_hex": f"0x{offset:X}", "length": len(data),
                "bytes": to_hex(data)}

    @app.post("/api/v1/json/validate")
    def validate_json(body: ValidateIn, session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        issues = contracts.validate(body.record)
        binary_checked = False
        if body.firmware_id is not None and not any(i.severity == "error" for i in issues):
            rec = firmware.get(session, body.firmware_id)
            issues += check_against_bin(body.record, vault.read(rec.blob.sha256))
            binary_checked = True
        errors = [i.to_dict() for i in issues if i.severity == "error"]
        return {"valid": not errors, "binary_checked": binary_checked, "errors": errors,
                "warnings": [i.to_dict() for i in issues if i.severity == "warning"]}

    @app.get("/api/v1/definitions")
    def list_definitions(q: str | None = None, category: str | None = None, limit: int = Query(50, ge=1, le=500),
                         session: Session = Depends(db), _: str = Depends(actor)) -> list[dict[str, Any]]:
        return [_definition_out(d, with_payload=False) for d in factory.search(session, q, category, limit)]

    @app.post("/api/v1/definitions", status_code=201)
    def create_definition(body: RecordIn, session: Session = Depends(db), who: str = Depends(actor)) -> dict[str, Any]:
        rev, checked = factory.create(session, body.record, who)
        return {**_revision_out(rev), "warnings": [w.to_dict() for w in checked.warnings]}

    @app.get("/api/v1/definitions/{record_id}")
    def get_definition(record_id: str, session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        return _definition_out(factory.get(session, record_id))

    @app.post("/api/v1/definitions/{record_id}/revisions", status_code=201)
    def add_revision(record_id: str, body: RecordIn, session: Session = Depends(db),
                     who: str = Depends(actor)) -> dict[str, Any]:
        rev, checked = factory.add_revision(session, record_id, body.record, who)
        return {**_revision_out(rev), "warnings": [w.to_dict() for w in checked.warnings]}

    @app.post("/api/v1/definitions/{record_id}/validate")
    def validate_definition(record_id: str, revision: int | None = None, session: Session = Depends(db),
                            _: str = Depends(actor)) -> dict[str, Any]:
        rev = factory.get_revision(session, record_id, revision)
        return {"record_id": record_id, "revision": rev.revision,
                **factory.check(session, json.loads(rev.payload)).as_dict()}

    @app.post("/api/v1/exports/preview")
    def export_preview(body: ExportIn, session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        return factory.export_preview(session, body.record_id, body.revision)

    @app.post("/api/v1/exports", status_code=201)
    def export(body: ExportIn, session: Session = Depends(db), who: str = Depends(actor)) -> dict[str, Any]:
        art = factory.export(session, body.record_id, body.revision, who)
        return {"id": art.id, "filename": art.filename, "path": art.path, "sha256": art.sha256}

    @app.post("/api/v1/json/import")
    def import_json(body: ImportIn, session: Session = Depends(db), who: str = Depends(actor)) -> dict[str, Any]:
        if not body.apply:
            return factory.import_preview(session, body.record)
        return factory.import_record(session, body.record, who)

    @app.get("/api/v1/review/queue")
    def review_queue(category: str | None = None, sha256: str | None = None, q: str | None = None,
                     limit: int = Query(50, ge=1, le=500), session: Session = Depends(db),
                     _: str = Depends(actor)) -> list[dict[str, Any]]:
        return review.queue(session, category, sha256, q, limit)

    @app.post("/api/v1/review/{record_id}/accept")
    def review_accept(record_id: str, body: ReviewIn, session: Session = Depends(db),
                      who: str = Depends(actor)) -> dict[str, Any]:
        return review.decide(session, factory, record_id, "accept", who, body.revision, body.note)

    @app.post("/api/v1/review/{record_id}/edit")
    def review_edit(record_id: str, body: EditIn, session: Session = Depends(db),
                    who: str = Depends(actor)) -> dict[str, Any]:
        return review.decide(session, factory, record_id, "edit", who, body.revision, body.note, body.changes,
                             body.approve)

    @app.post("/api/v1/review/{record_id}/reject")
    def review_reject(record_id: str, body: ReviewIn, session: Session = Depends(db),
                      who: str = Depends(actor)) -> dict[str, Any]:
        return review.decide(session, factory, record_id, "reject", who, body.revision, body.note)

    @app.get("/api/v1/review/{record_id}/history")
    def review_history(record_id: str, session: Session = Depends(db), _: str = Depends(actor)) -> list[dict[str, Any]]:
        return review.history(session, factory, record_id)

    @app.post("/api/v1/sources/import/ols-json")
    async def import_ols(file: UploadFile = File(...), firmware_id: int = Form(...), apply: bool = Form(False),
                         aliases: str | None = Form(None), session: Session = Depends(db),
                         who: str = Depends(actor)) -> dict[str, Any]:
        raw = await file.read(settings.max_bin_bytes + 1)
        try:
            doc = json.loads(raw.decode("utf-8-sig"))
            alias_map = json.loads(aliases) if aliases else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AktoolError("INVALID_JSON", f"could not parse JSON: {exc}", field="file", status_code=422) from None
        return sources.import_ols_json(session, factory, vault, firmware_id, doc, file.filename or "ols.json",
                                       apply, who, alias_map)

    @app.post("/api/v1/sources/import/kp")
    async def import_kp(file: UploadFile = File(...), firmware_id: int = Form(...), apply: bool = Form(False),
                        base_address: str | None = Form(None), session: Session = Depends(db),
                        who: str = Depends(actor)) -> dict[str, Any]:
        data = await file.read(settings.max_bin_bytes + 1)
        try:
            base = int(base_address, 0) if base_address else None
        except ValueError:
            raise AktoolError("INVALID_BASE_ADDRESS", "base_address must be a number such as 0x80000000",
                              field="base_address", status_code=422) from None
        return sources.import_kp(session, factory, vault, firmware_id, data, file.filename or "maps.kp", apply, who,
                                 base)

    @app.post("/api/v1/exports/ols-json")
    def export_ols(body: OlsExportIn, session: Session = Depends(db), _: str = Depends(actor)) -> dict[str, Any]:
        records = [json.loads(factory.get_revision(session, rid).payload) for rid in body.record_ids]
        try:
            return ols_json.export_document(records, decimal_comma=body.decimal_comma)
        except ValueError as exc:
            raise AktoolError("EXPORT_UNSUPPORTED", str(exc), status_code=422) from None

    return app


def _revision_out(rev) -> dict[str, Any]:
    return {"record_id": rev.definition.record_id, "revision": rev.revision, "review_state": rev.review_state,
            "payload_hash": rev.payload_hash, "binary_verified": rev.binary_verified,
            "created_by": rev.created_by, "created_at": rev.created_at.isoformat()}


def _definition_out(d, with_payload: bool = True) -> dict[str, Any]:
    out = {"record_id": d.record_id, "category": d.category, "concept_key": d.concept_key, "sha256": d.sha256,
           "software_id": d.software_id, "calibration_id": d.calibration_id,
           "latest_revision": d.revisions[-1].revision if d.revisions else None}
    if with_payload:
        out["revisions"] = [{**_revision_out(r), "payload": json.loads(r.payload)} for r in d.revisions]
    return out


def _firmware_out(session: Session, rec: FirmwareRecord, with_relations: bool = True) -> dict[str, Any]:
    out = {
        "id": rec.id, "file_name_original": rec.file_name_original, "file_role": rec.file_role,
        "file_size": rec.blob.size, "md5": rec.blob.md5, "sha256": rec.blob.sha256,
        "software_id": rec.software_id, "calibration_id": rec.calibration_id, "ecu_label": rec.ecu_label,
        "vehicle_brand": rec.vehicle_brand, "vehicle_model": rec.vehicle_model, "ecu_vendor": rec.ecu_vendor,
        "ecu_family": rec.ecu_family, "processor": rec.processor, "base_address": rec.base_address,
        "read_tool": rec.read_tool, "read_method": rec.read_method, "notes": rec.notes,
        "created_at": rec.created_at.isoformat(), "updated_at": rec.updated_at.isoformat(),
    }
    if with_relations:
        out["relations"] = [{"id": r.id, "source_id": r.source_id, "target_id": r.target_id,
                             "relation_type": r.relation_type, "confidence": r.confidence}
                            for r in firmware.relations_of(session, rec.id)]
    return out
