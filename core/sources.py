"""Source import orchestration (FR-05): run an importer (OLS map-pack JSON, WinOLS .kp) against a firmware
in the vault, then either preview the result or store each proposal as a draft definition through the JSON
factory."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from core import audit, firmware
from core.errors import AktoolError
from core.importers import kp_binary, ols_json
from core.jsonfactory import JsonFactory
from core.vault import BinVault


def import_ols_json(session: Session, factory: JsonFactory, vault: BinVault, firmware_id: int, doc: Any,
                    source_name: str, apply: bool, actor: str,
                    aliases: dict[str, str] | None = None) -> dict[str, Any]:
    rec = firmware.get(session, firmware_id)
    try:
        report = ols_json.import_document(doc, vault.read(rec.blob.sha256), _firmware_info(rec), aliases, source_name)
    except ols_json.OlsFormatError as exc:
        raise AktoolError("UNSUPPORTED_SOURCE_FORMAT", str(exc), field="file", status_code=422) from None
    return _store(session, factory, rec, report, source_name, apply, actor)


def import_kp(session: Session, factory: JsonFactory, vault: BinVault, firmware_id: int, data: bytes,
              source_name: str, apply: bool, actor: str, base_address: int | None = None) -> dict[str, Any]:
    """Read a WinOLS .kp map pack against a firmware in the vault and propose its maps as drafts."""
    rec = firmware.get(session, firmware_id)
    bin_data = vault.read(rec.blob.sha256)
    try:
        parsed = kp_binary.parse_kp(data, rom_size=len(bin_data), base_address=base_address)
    except kp_binary.KpParseError as exc:
        raise AktoolError("UNSUPPORTED_SOURCE_FORMAT", str(exc), field="file", status_code=422) from None
    doc, source, notes = kp_binary.to_ols_document(parsed, source_name)
    report = ols_json.import_document(doc, bin_data, _firmware_info(rec), source_name=source_name, source=source)
    for index, map_notes in enumerate(notes):
        for note in map_notes:
            report.warnings.append({"index": index, "name": doc["maps"][index]["Name"], "message": note})
    report.total_maps += len(parsed.rejected)
    return {**_store(session, factory, rec, report, source_name, apply, actor), **parsed.info()}


def _firmware_info(rec: Any) -> dict[str, Any]:
    return {"sha256": rec.blob.sha256, "md5": rec.blob.md5, "file_size": rec.blob.size,
            "software_id": rec.software_id, "calibration_id": rec.calibration_id, "ecu_vendor": rec.ecu_vendor,
            "ecu_family": rec.ecu_family, "processor": rec.processor}


def _store(session: Session, factory: JsonFactory, rec: Any, report: ols_json.ImportReport, source_name: str,
           apply: bool, actor: str) -> dict[str, Any]:
    """Preview the proposals, or store each new one as a draft definition through the JSON factory."""
    items = []
    counts = {"created": 0, "unchanged": 0, "rejected": 0, "would_create": 0}
    for record in report.records:
        if _already_imported(session, factory, record):
            counts["unchanged"] += 1
            items.append({"record_id": record["record_id"], "name": record["name"], "action": "unchanged",
                          "file_offset": record["file_offset"], "errors": [], "warnings": []})
            continue
        preview = factory.import_preview(session, record)
        item = {"record_id": record["record_id"], "name": record["name"], "action": preview["action"],
                "file_offset": record["file_offset"], "errors": preview["errors"], "warnings": preview["warnings"]}
        if preview["action"] == "create":
            if apply:
                factory.create(session, record, actor)
                item["action"] = "created"
                counts["created"] += 1
            else:
                counts["would_create"] += 1
        elif preview["action"] == "unchanged":
            counts["unchanged"] += 1
        else:
            counts["rejected"] += 1
        items.append(item)
    if apply:
        audit.record(session, actor, "source.import", "firmware", rec.id, format=report.format,
                     source_name=source_name, **counts, skipped=len(report.skipped))
        session.commit()
    return {**report.summary(), "applied": apply, "firmware_id": rec.id, **counts, "items": items}


# Fields that change on every import run and carry no meaning about the map itself.
_VOLATILE = ("created_at", "updated_at", "provenance")


def _already_imported(session: Session, factory: JsonFactory, record: dict[str, Any]) -> bool:
    """True when this record_id exists and its latest revision says the same thing, ignoring import time."""
    try:
        latest = factory.get_revision(session, record["record_id"])
    except AktoolError:
        return False
    stored = json.loads(latest.payload)
    strip = lambda r: {k: v for k, v in r.items() if k not in _VOLATILE + ("revision", "review_state", "reviewer")}
    return strip(stored) == strip(json.loads(json.dumps(record)))
