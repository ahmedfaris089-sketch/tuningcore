"""JSON Factory (FR-10): definitions, immutable revisions, validation, export and import.

Every payload is canonicalized before hashing, so the same meaning always has the same hash and an
export followed by an import is recognised as the same revision.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core import audit
from core.db import Definition, DefinitionRevision, ExportArtifact, FirmwareBlob
from core.errors import AktoolError, NotFound
from core.hexbytes import normalize
from core.validators import ContractValidator, Issue, check_against_bin
from core.vault import BinVault

HEX_FIELDS = ("original_bytes", "on_bytes", "off_bytes", "original_raw_bytes", "proposed_bytes")
TABLE_FIELDS = ("mask_table", "error_path_table", "tables")
CONCEPT_FIELD = {"function_on_off": "function_key", "function_map_table": "map_key",
                 "bosch_dtc": "dtc_code", "non_bosch_dtc": "dtc_code"}
TRUSTED_STATES = ("approved", "validated")


@dataclass
class Checked:
    record: dict[str, Any]
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    binary_verified: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"valid": not self.errors, "binary_verified": self.binary_verified,
                "errors": [i.to_dict() for i in self.errors], "warnings": [i.to_dict() for i in self.warnings]}


def canonicalize(record: dict[str, Any]) -> dict[str, Any]:
    """Uppercase canonical hex everywhere; leave every other value untouched."""
    out = copy.deepcopy(record)
    for key in HEX_FIELDS:
        if isinstance(out.get(key), str):
            out[key] = normalize(out[key])
    for table in TABLE_FIELDS:
        for entry in out.get(table) or []:
            if isinstance(entry, dict) and isinstance(entry.get("original_bytes"), str):
                entry["original_bytes"] = normalize(entry["original_bytes"])
    return out


def canonical_bytes(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def payload_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def export_filename(record: dict[str, Any]) -> str:
    def safe(text: str | None) -> str:
        return re.sub(r"_+", "_", re.sub(r"[^A-Za-z0-9]+", "_", text or "")).strip("_")

    name = safe(record["name"]) or safe(record.get(CONCEPT_FIELD[record["category"]])) or "record"
    parts = [name[:60], record["category"], safe(record["software_id"]) or "NA",
             safe(record["calibration_id"]) or "NA", f"r{record['revision']}"]
    return "_".join(parts) + ".json"


class JsonFactory:
    def __init__(self, contracts: ContractValidator, vault: BinVault, export_dir: Path):
        self.contracts = contracts
        self.vault = vault
        self.export_dir = Path(export_dir)

    # ---- validation -------------------------------------------------------------------------
    def check(self, session: Session, record: Any) -> Checked:
        if not isinstance(record, dict):
            return Checked({}, [Issue("error", "NOT_AN_OBJECT", "$", "record must be a JSON object")])
        try:
            record = canonicalize(record)
        except ValueError as exc:
            return Checked(record, [Issue("error", "SCHEMA_VIOLATION", "$", str(exc))])
        issues = self.contracts.validate(record)
        result = Checked(record, [i for i in issues if i.severity == "error"],
                         [i for i in issues if i.severity == "warning"])
        if result.errors:
            return result
        blob = session.scalar(select(FirmwareBlob).where(FirmwareBlob.sha256 == record["sha256"]))
        if blob is None:
            result.warnings.append(Issue("warning", "BIN_NOT_IN_VAULT", "$.sha256",
                                         "the referenced BIN is not in the vault, so bytes were not checked"))
        else:
            bin_issues = check_against_bin(record, self.vault.read(blob.sha256))
            result.errors += [i for i in bin_issues if i.severity == "error"]
            result.binary_verified = not result.errors
        if record["review_state"] in TRUSTED_STATES and not result.binary_verified and not result.errors:
            result.errors.append(Issue("error", "TRUSTED_NEEDS_BIN", "$.review_state",
                                       "approved/validated records must be checked against their BIN"))
        return result

    # ---- definitions and revisions -------------------------------------------------------------
    def get(self, session: Session, record_id: str) -> Definition:
        d = session.scalar(select(Definition).where(Definition.record_id == record_id))
        if d is None:
            raise NotFound("DEFINITION_NOT_FOUND", "no definition with this record_id", details={"record_id": record_id})
        return d

    def get_revision(self, session: Session, record_id: str, revision: int | None = None) -> DefinitionRevision:
        d = self.get(session, record_id)
        if revision is None:
            return d.revisions[-1]
        for r in d.revisions:
            if r.revision == revision:
                return r
        raise NotFound("REVISION_NOT_FOUND", "no such revision", details={"record_id": record_id, "revision": revision})

    def search(self, session: Session, q: str | None = None, category: str | None = None,
               limit: int = 50) -> list[Definition]:
        stmt = select(Definition)
        if category:
            stmt = stmt.where(Definition.category == category)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(Definition.record_id.ilike(like), Definition.concept_key.ilike(like),
                                  Definition.software_id.ilike(like), Definition.calibration_id.ilike(like),
                                  Definition.sha256 == q.lower()))
        return list(session.scalars(stmt.order_by(Definition.id.desc()).limit(limit)))

    def create(self, session: Session, record: dict[str, Any], actor: str) -> tuple[DefinitionRevision, Checked]:
        checked = self._require_valid(session, record)
        rec = checked.record
        if rec["revision"] != 1:
            raise AktoolError("REVISION_SEQUENCE", "a new definition must start at revision 1", field="revision")
        if session.scalar(select(Definition.id).where(Definition.record_id == rec["record_id"])) is not None:
            raise AktoolError("RECORD_EXISTS", "record_id already exists; add a revision instead",
                              field="record_id", status_code=409)
        d = Definition(record_id=rec["record_id"], category=rec["category"],
                       concept_key=str(rec[CONCEPT_FIELD[rec["category"]]]), sha256=rec["sha256"],
                       software_id=rec["software_id"], calibration_id=rec["calibration_id"])
        session.add(d)
        session.flush()
        rev = self._insert_revision(session, d, rec, None, checked.binary_verified, actor)
        audit.record(session, actor, "definition.create", "definition", d.record_id, revision=1,
                     payload_hash=rev.payload_hash)
        session.commit()
        return rev, checked

    def add_revision(self, session: Session, record_id: str, record: dict[str, Any],
                     actor: str) -> tuple[DefinitionRevision, Checked]:
        d = self.get(session, record_id)
        checked = self._require_valid(session, record)
        rec = checked.record
        latest = d.revisions[-1]
        if rec["record_id"] != d.record_id or rec["category"] != d.category:
            raise AktoolError("IDENTITY_CHANGED", "record_id and category cannot change between revisions")
        if rec["revision"] != latest.revision + 1:
            raise AktoolError("REVISION_SEQUENCE", f"next revision must be {latest.revision + 1}", field="revision",
                              details={"latest": latest.revision, "got": rec["revision"]}, status_code=409)
        rev = self._insert_revision(session, d, rec, latest.id, checked.binary_verified, actor)
        audit.record(session, actor, "definition.revise", "definition", d.record_id, revision=rev.revision,
                     parent=latest.revision, payload_hash=rev.payload_hash)
        session.commit()
        return rev, checked

    # ---- export -------------------------------------------------------------------------------
    def export_preview(self, session: Session, record_id: str, revision: int | None) -> dict[str, Any]:
        rev = self.get_revision(session, record_id, revision)
        record = json.loads(rev.payload)
        checked = self.check(session, record)
        if rev.review_state not in TRUSTED_STATES:
            checked.errors.append(Issue("error", "NOT_APPROVED", "$.review_state",
                                        "only approved or validated revisions can be exported"))
        if record["software_id"] is None or record["calibration_id"] is None:
            checked.errors.append(Issue("error", "EXPORT_ID_MISSING", "$.software_id",
                                        "software_id and calibration_id are required for export"))
        if checked.errors:
            checked.binary_verified = False
        return {"record_id": record_id, "revision": rev.revision, "filename": export_filename(record),
                "content": _pretty(record), **checked.as_dict()}

    def export(self, session: Session, record_id: str, revision: int | None, actor: str) -> ExportArtifact:
        preview = self.export_preview(session, record_id, revision)
        if not preview["valid"]:
            raise AktoolError("EXPORT_BLOCKED", "export failed validation", details={"errors": preview["errors"]},
                              status_code=422)
        rev = self.get_revision(session, record_id, preview["revision"])
        data = preview["content"].encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        self.export_dir.mkdir(parents=True, exist_ok=True)
        path = (self.export_dir / preview["filename"]).resolve()
        if self.export_dir.resolve() not in path.parents:
            raise AktoolError("PATH_OUTSIDE_EXPORTS", "export path escapes the export directory")
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AktoolError("EXPORT_FILE_CONFLICT", "a different file with this name already exists",
                                  details={"filename": preview["filename"]}, status_code=409)
        else:
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, path)
        art = ExportArtifact(revision_id=rev.id, schema_version=json.loads(rev.payload)["schema_version"],
                             filename=preview["filename"], path=str(path), sha256=digest, created_by=actor)
        session.add(art)
        session.flush()
        audit.record(session, actor, "export.create", "export", art.id, record_id=record_id,
                     revision=rev.revision, sha256=digest)
        session.commit()
        return art

    # ---- import -------------------------------------------------------------------------------
    def import_preview(self, session: Session, record: Any) -> dict[str, Any]:
        checked = self.check(session, record)
        out: dict[str, Any] = {"action": "reject", **checked.as_dict()}
        if checked.errors:
            return out
        rec = checked.record
        d = session.scalar(select(Definition).where(Definition.record_id == rec["record_id"]))
        h = payload_hash(rec)
        if d is None:
            out["action"] = "create" if rec["revision"] == 1 else "reject"
            if rec["revision"] != 1:
                out["errors"].append({"severity": "error", "code": "REVISION_SEQUENCE", "path": "$.revision",
                                      "message": "unknown record_id must start at revision 1"})
        else:
            same = next((r for r in d.revisions if r.revision == rec["revision"]), None)
            latest = d.revisions[-1].revision
            if same is not None and same.payload_hash == h:
                out["action"] = "unchanged"
            elif same is not None:
                out["action"] = "reject"
                out["errors"].append({"severity": "error", "code": "REVISION_CONFLICT", "path": "$.revision",
                                      "message": f"revision {rec['revision']} exists with different content"})
            elif rec["revision"] == latest + 1:
                out["action"] = "add_revision"
            else:
                out["action"] = "reject"
                out["errors"].append({"severity": "error", "code": "REVISION_SEQUENCE", "path": "$.revision",
                                      "message": f"next revision must be {latest + 1}"})
        out["valid"] = not out["errors"]
        out["payload_hash"] = h
        return out

    def import_record(self, session: Session, record: dict[str, Any], actor: str) -> dict[str, Any]:
        preview = self.import_preview(session, record)
        if preview["action"] == "create":
            rev, _ = self.create(session, record, actor)
        elif preview["action"] == "add_revision":
            rev, _ = self.add_revision(session, record["record_id"], record, actor)
        elif preview["action"] == "unchanged":
            rev = self.get_revision(session, record["record_id"], record["revision"])
        else:
            raise AktoolError("IMPORT_REJECTED", "record cannot be imported", details={"errors": preview["errors"]},
                              status_code=422)
        return {"action": preview["action"], "record_id": record["record_id"], "revision": rev.revision,
                "payload_hash": rev.payload_hash}

    # ---- helpers ------------------------------------------------------------------------------
    def _require_valid(self, session: Session, record: Any) -> Checked:
        checked = self.check(session, record)
        if checked.errors:
            raise AktoolError("RECORD_INVALID", "record failed validation", details=checked.as_dict(),
                              status_code=422)
        return checked

    @staticmethod
    def _insert_revision(session: Session, d: Definition, rec: dict[str, Any], parent_id: int | None,
                         verified: bool, actor: str) -> DefinitionRevision:
        rev = DefinitionRevision(definition_id=d.id, revision=rec["revision"], parent_revision_id=parent_id,
                                 review_state=rec["review_state"], payload=canonical_bytes(rec).decode("utf-8"),
                                 payload_hash=payload_hash(rec), binary_verified=verified, created_by=actor)
        session.add(rev)
        session.flush()
        session.refresh(d)
        return rev


def _pretty(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, ensure_ascii=False) + "\n"
