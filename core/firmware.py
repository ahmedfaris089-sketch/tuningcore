"""Firmware intake, metadata and relations (FR-01..FR-03)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core import audit
from core.db import FirmwareBlob, FirmwareRecord, FirmwareRelation
from core.errors import AktoolError, NotFound
from core.vault import BinVault

EDITABLE_FIELDS = ("software_id", "calibration_id", "ecu_label", "vehicle_brand", "vehicle_model", "ecu_vendor",
                   "ecu_family", "processor", "base_address", "read_tool", "read_method", "notes", "file_role")
# Directed "child -> parent" edges that must never form a cycle.
PARENT_EDGES = ("modified_from", "variant_of", "supersedes")


def ingest(session: Session, vault: BinVault, data: bytes, file_name: str, actor: str,
           metadata: dict[str, Any]) -> tuple[FirmwareRecord, bool]:
    """Store a BIN and its record. Re-uploading identical bytes returns the existing record."""
    blob_info = vault.put(data)
    blob = session.scalar(select(FirmwareBlob).where(FirmwareBlob.sha256 == blob_info.sha256))
    if blob is None:
        blob = FirmwareBlob(sha256=blob_info.sha256, md5=blob_info.md5, size=blob_info.size,
                            vault_path=str(blob_info.path))
        session.add(blob)
        session.flush()
    existing = session.scalar(select(FirmwareRecord).where(FirmwareRecord.blob_id == blob.id))
    if existing is not None:
        audit.record(session, actor, "firmware.duplicate_upload", "firmware", existing.id, file_name=file_name)
        session.commit()
        return existing, False

    clean = {k: v for k, v in metadata.items() if k in EDITABLE_FIELDS and v not in (None, "")}
    rec = FirmwareRecord(blob_id=blob.id, file_name_original=_safe_display_name(file_name), **clean)
    session.add(rec)
    session.flush()
    audit.record(session, actor, "firmware.create", "firmware", rec.id, sha256=blob.sha256, size=blob.size)
    session.commit()
    return rec, True


def get(session: Session, firmware_id: int) -> FirmwareRecord:
    rec = session.get(FirmwareRecord, firmware_id)
    if rec is None or rec.deleted:
        raise NotFound("FIRMWARE_NOT_FOUND", "no firmware with this id", details={"firmware_id": firmware_id})
    return rec


def search(session: Session, q: str | None, limit: int = 50) -> list[FirmwareRecord]:
    stmt = select(FirmwareRecord).join(FirmwareBlob).where(FirmwareRecord.deleted.is_(False))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(FirmwareBlob.sha256 == q.lower(), FirmwareBlob.md5 == q.lower(),
                              FirmwareRecord.software_id.ilike(like), FirmwareRecord.calibration_id.ilike(like),
                              FirmwareRecord.ecu_family.ilike(like), FirmwareRecord.ecu_label.ilike(like),
                              FirmwareRecord.file_name_original.ilike(like)))
    return list(session.scalars(stmt.order_by(FirmwareRecord.id.desc()).limit(limit)))


def update(session: Session, firmware_id: int, changes: dict[str, Any], actor: str) -> FirmwareRecord:
    rec = get(session, firmware_id)
    unknown = set(changes) - set(EDITABLE_FIELDS)
    if unknown:
        raise AktoolError("FIELD_NOT_EDITABLE", "these fields cannot be edited", details={"fields": sorted(unknown)})
    before = {k: getattr(rec, k) for k in changes}
    for k, v in changes.items():
        setattr(rec, k, v)
    audit.record(session, actor, "firmware.update", "firmware", rec.id, before=before, after=changes)
    session.commit()
    return rec


def add_relation(session: Session, source_id: int, target_id: int, relation_type: str, actor: str,
                 confidence: float = 1.0, source: str = "manual") -> FirmwareRelation:
    get(session, source_id)
    get(session, target_id)
    if source_id == target_id:
        raise AktoolError("SELF_RELATION", "a firmware cannot be related to itself", field="target_id")
    if relation_type == "original_of":  # store one direction only: child modified_from parent
        source_id, target_id, relation_type = target_id, source_id, "modified_from"
    if relation_type in PARENT_EDGES and _reaches(session, start=target_id, goal=source_id):
        raise AktoolError("RELATION_CYCLE", "this relation would create a parent cycle",
                          details={"source_id": source_id, "target_id": target_id})
    dup = session.scalar(select(FirmwareRelation).where(FirmwareRelation.source_id == source_id,
                                                        FirmwareRelation.target_id == target_id,
                                                        FirmwareRelation.relation_type == relation_type))
    if dup is not None:
        return dup
    rel = FirmwareRelation(source_id=source_id, target_id=target_id, relation_type=relation_type,
                           confidence=confidence, source=source, reviewer=actor)
    session.add(rel)
    session.flush()
    audit.record(session, actor, "relation.create", "relation", rel.id, source_id=source_id, target_id=target_id,
                 relation_type=relation_type)
    session.commit()
    return rel


def relations_of(session: Session, firmware_id: int) -> list[FirmwareRelation]:
    return list(session.scalars(select(FirmwareRelation).where(
        or_(FirmwareRelation.source_id == firmware_id, FirmwareRelation.target_id == firmware_id))))


def _reaches(session: Session, start: int, goal: int) -> bool:
    seen, stack = set(), [start]
    while stack:
        node = stack.pop()
        if node == goal:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(session.scalars(select(FirmwareRelation.target_id).where(
            FirmwareRelation.source_id == node, FirmwareRelation.relation_type.in_(PARENT_EDGES))))
    return False


def _safe_display_name(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return base[:255] or "upload.bin"
