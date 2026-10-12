"""Recognition of related files and transfer of approved records to them (FR-04).

`identify` says which stored BINs look like a given one and how closely. `transfer` proposes a related BIN's
approved records on this BIN, as drafts for the review queue, only where the bytes show the record still sits
where it says: the same bytes (with surrounding context) at the same offset, the same bytes found exactly once
at another offset, or, for a map whose values were changed, identical axes at the same offset. Nothing is
guessed: a record that cannot be located this way is reported as skipped, with the reason.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core import audit, fingerprint, firmware
from core.db import Definition, DefinitionRevision, FingerprintBlock, FirmwareFingerprint, FirmwareRecord
from core.errors import AktoolError
from core.hexbytes import from_hex, to_hex
from core.importers import ols_json
from core.jsonfactory import CONCEPT_FIELD, TRUSTED_STATES, JsonFactory
from core.sources import already_imported
from core.validators import check_against_bin
from core.vault import BinVault

VARIANT_RATIO = 0.80  # share of informative blocks identical at the same offset, same file size
FAMILY_RATIO = 0.20  # share of informative blocks found anywhere in the other file
CONTEXT = 32  # bytes on each side of a record that must match too, so a short pattern is not found by chance
MIN_PATTERN = 16  # shortest record bytes searched on their own when the context around them changed
METHODS = {
    "identical_bytes": (0.9, "record bytes and 32 bytes of context identical at the same offset"),
    "relocated": (0.8, "record bytes and context found exactly once at a shifted offset"),
    "axes_match": (0.7, "map axes identical at the same offset; map values read from this BIN"),
    "same_layout": (0.5, "map and axes changed, but this BIN is a same-size variant of the source; values and axes "
                         "read from this BIN at the same offset"),
}
LEVELS = ("exact", "variant", "family_candidate", "unknown")
_TYPE_SIZES = {"uint8": 1, "int8": 1, "uint16": 2, "int16": 2, "uint32": 4, "int32": 4, "float32": 4, "float64": 8}


# ---- identify -----------------------------------------------------------------------------------------
def identify(session: Session, vault: BinVault, firmware_id: int, limit: int = 10) -> dict[str, Any]:
    rec = firmware.get(session, firmware_id)
    fingerprint.backfill(session, vault)
    fp = session.get(FirmwareFingerprint, rec.blob_id)
    mine = fp.blocks.split(",")
    informative = [h for h in mine if h]
    distinct = sorted(set(informative))
    my_ids = set(json.loads(fp.identifiers))

    shared: dict[int, int] = {}
    for i in range(0, len(distinct), 500):
        rows = session.execute(
            select(FingerprintBlock.blob_id, func.count(func.distinct(FingerprintBlock.hash)))
            .where(FingerprintBlock.hash.in_(distinct[i:i + 500]), FingerprintBlock.blob_id != rec.blob_id)
            .group_by(FingerprintBlock.blob_id)).all()
        for blob_id, n in rows:
            shared[blob_id] = shared.get(blob_id, 0) + n
    if my_ids:
        for other in session.scalars(select(FirmwareFingerprint).where(FirmwareFingerprint.blob_id != rec.blob_id)):
            if my_ids & set(json.loads(other.identifiers)):
                shared.setdefault(other.blob_id, 0)

    data = vault.read(rec.blob.sha256)
    candidates = []
    for blob_id, n_shared in shared.items():
        other_rec = session.scalar(select(FirmwareRecord).where(FirmwareRecord.blob_id == blob_id,
                                                                FirmwareRecord.deleted.is_(False)))
        if other_rec is None:
            continue
        other_fp = session.get(FirmwareFingerprint, blob_id)
        theirs = other_fp.blocks.split(",")
        same_size = other_rec.blob.size == rec.blob.size
        same_offset = sum(1 for a, b in zip(mine, theirs) if a and a == b)
        same_offset_ratio = same_offset / len(informative) if informative and same_size else 0.0
        shared_ratio = n_shared / len(distinct) if distinct else 0.0
        common_ids = sorted(my_ids & set(json.loads(other_fp.identifiers)))
        if same_size and same_offset_ratio >= VARIANT_RATIO:
            level = "variant"
        elif shared_ratio >= FAMILY_RATIO or common_ids:
            level = "family_candidate"
        else:
            continue
        item = {"firmware_id": other_rec.id, "file_name": other_rec.file_name_original,
                "sha256": other_rec.blob.sha256, "file_size": other_rec.blob.size,
                "software_id": other_rec.software_id, "ecu_family": other_rec.ecu_family, "level": level,
                "same_offset_block_ratio": round(same_offset_ratio, 4), "shared_block_ratio": round(shared_ratio, 4),
                "shared_identifiers": common_ids, "differing_bytes": None,
                **_record_counts(session, other_rec.blob.sha256)}
        if same_size:
            item["differing_bytes"] = _differing_bytes(data, vault.read(other_rec.blob.sha256), mine, theirs,
                                                       fp.block_size)
        candidates.append(item)
    candidates.sort(key=lambda c: (LEVELS.index(c["level"]), -c["same_offset_block_ratio"],
                                   -c["shared_block_ratio"], -c["trusted_records"]))
    own = _record_counts(session, rec.blob.sha256)
    level = "exact" if own["trusted_records"] else (candidates[0]["level"] if candidates else "unknown")
    return {"firmware_id": rec.id, "sha256": rec.blob.sha256, "file_size": rec.blob.size, "match_level": level,
            "own_trusted_records": own["trusted_records"], "own_draft_records": own["draft_records"],
            "identifiers": sorted(my_ids), "block_size": fp.block_size, "informative_blocks": len(informative),
            "candidates": candidates[:limit]}


def _record_counts(session: Session, sha256: str) -> dict[str, int]:
    trusted = drafts = 0
    for _, rev in _latest_revisions(session, sha256):
        if rev.review_state in TRUSTED_STATES and rev.binary_verified:
            trusted += 1
        elif rev.review_state == "draft":
            drafts += 1
    return {"trusted_records": trusted, "draft_records": drafts}


def _latest_revisions(session: Session, sha256: str) -> list[tuple[Definition, DefinitionRevision]]:
    latest = (select(DefinitionRevision.definition_id, func.max(DefinitionRevision.revision).label("rev"))
              .group_by(DefinitionRevision.definition_id).subquery())
    stmt = (select(Definition, DefinitionRevision)
            .join(latest, latest.c.definition_id == Definition.id)
            .join(DefinitionRevision, (DefinitionRevision.definition_id == Definition.id)
                  & (DefinitionRevision.revision == latest.c.rev))
            .where(Definition.sha256 == sha256).order_by(Definition.id))
    return [(d, rev) for d, rev in session.execute(stmt).all()]


def _differing_bytes(a: bytes, b: bytes, ha: list[str], hb: list[str], block_size: int) -> int:
    total = 0
    for n, (x, y) in enumerate(zip(ha, hb)):
        if x and x == y:
            continue
        start = n * block_size
        total += sum(1 for p, q in zip(a[start:start + block_size], b[start:start + block_size]) if p != q)
    return total


# ---- transfer -----------------------------------------------------------------------------------------
def transfer(session: Session, factory: JsonFactory, vault: BinVault, firmware_id: int, source_firmware_id: int,
             apply: bool, actor: str, record_ids: list[str] | None = None) -> dict[str, Any]:
    if firmware_id == source_firmware_id:
        raise AktoolError("SAME_FIRMWARE", "source and target are the same firmware", field="source_firmware_id")
    target = firmware.get(session, firmware_id)
    source = firmware.get(session, source_firmware_id)
    t_data = vault.read(target.blob.sha256)
    s_data = vault.read(source.blob.sha256)
    same_layout = len(t_data) == len(s_data) and _same_offset_ratio(session, source, target) >= VARIANT_RATIO
    trusted = [(d, rev) for d, rev in _latest_revisions(session, source.blob.sha256)
               if rev.review_state in TRUSTED_STATES and rev.binary_verified]
    if record_ids is not None:
        wanted = set(record_ids)
        missing = sorted(wanted - {d.record_id for d, _ in trusted})
        if missing:
            raise AktoolError("NOT_TRUSTED_SOURCE_RECORDS", "these records are not approved records of the source",
                              field="record_ids", details={"record_ids": missing})
        trusted = [(d, rev) for d, rev in trusted if d.record_id in wanted]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    counts = {"created": 0, "would_create": 0, "unchanged": 0, "exists": 0, "skipped": 0, "rejected": 0}
    by_method = {m: 0 for m in METHODS}
    items = []
    for d, rev in trusted:
        src = json.loads(rev.payload)
        item: dict[str, Any] = {"source_record_id": d.record_id, "source_revision": rev.revision,
                                "name": src["name"], "category": d.category, "method": None, "delta": None}
        method, delta, reason = _locate(src, s_data, t_data, same_layout)
        record = None
        if method is not None:
            record = _rebase(src, rev.revision, method, delta, source, target, t_data, now)
            issues = [i for i in check_against_bin(record, t_data) if i.severity == "error"]
            if issues:
                method, reason = None, issues[0].code
        if method is None:
            item.update(action="skipped", reason=reason)
            counts["skipped"] += 1
            items.append(item)
            continue
        item.update(method=method, delta=delta, record_id=record["record_id"], file_offset=record["file_offset"])
        clash = session.scalar(select(Definition.record_id).where(
            Definition.sha256 == target.blob.sha256, Definition.category == d.category,
            Definition.concept_key == d.concept_key, Definition.record_id != record["record_id"]))
        if already_imported(session, factory, record):
            item["action"] = "unchanged"
        elif clash is not None:
            item.update(action="exists", existing_record_id=clash)
        else:
            preview = factory.import_preview(session, record)
            if preview["action"] != "create":
                item.update(action="rejected", errors=preview["errors"])
            elif apply:
                factory.create(session, record, actor)
                item["action"] = "created"
            else:
                item["action"] = "would_create"
        counts[item["action"]] += 1
        if item["action"] in ("created", "would_create"):
            by_method[method] += 1
        items.append(item)
    if apply:
        audit.record(session, actor, "recognition.transfer", "firmware", target.id,
                     source_firmware_id=source.id, **counts)
        session.commit()
    return {"firmware_id": target.id, "source_firmware_id": source.id, "applied": apply,
            "same_layout": same_layout, "source_trusted_records": len(trusted), **counts, "by_method": by_method, "items": items}


def _locate(src: dict[str, Any], s: bytes, t: bytes,
            same_layout: bool) -> tuple[str | None, int | None, str | None]:
    """Where this record's bytes sit in the target: (method, delta, None) or (None, None, reason)."""
    off = src["file_offset"]
    orig = from_hex(src["original_bytes"])
    if s[off:off + len(orig)] != orig:
        return None, None, "SOURCE_BYTES_MISMATCH"
    c_start, c_end = max(0, off - CONTEXT), min(len(s), off + len(orig) + CONTEXT)
    context = s[c_start:c_end]
    reason = "NOT_FOUND"
    if t[c_start:c_end] == context:
        if _axes_match(src, s, t, 0):
            return "identical_bytes", 0, None
        reason = "AXES_DIFFER"
    else:
        for pattern, p_start in ((context, c_start), (orig, off)):
            if pattern is orig and len(orig) < MIN_PATTERN:
                continue
            hits = _find(t, pattern, limit=2)
            if len(hits) > 1:
                reason = "PATTERN_NOT_UNIQUE"
                continue
            if hits:
                delta = hits[0] - p_start
                if _axes_match(src, s, t, delta):
                    return ("identical_bytes" if delta == 0 else "relocated"), delta, None
                reason = "AXES_DIFFER"
                break

    is_map = src["category"] == "function_map_table"
    if is_map and len(s) == len(t):
        if any(a.get("source") == "stored" for a in src.get("axes", [])) and _axes_match(src, s, t, 0):
            return "axes_match", 0, None
        if same_layout:
            return "same_layout", 0, None
    return None, None, reason


def _find(data: bytes, pattern: bytes, limit: int) -> list[int]:
    hits, start = [], 0
    while len(hits) < limit:
        at = data.find(pattern, start)
        if at < 0:
            break
        hits.append(at)
        start = at + 1
    return hits


def _axes_match(src: dict[str, Any], s: bytes, t: bytes, delta: int) -> bool:
    """Every stored axis of a map has identical bytes in the target at the same shift."""
    for axis in src.get("axes", []):
        if axis.get("source") != "stored":
            continue
        size = _TYPE_SIZES.get(axis.get("data_type"))
        off = axis.get("file_offset")
        if size is None or off is None or off + delta < 0:
            return False
        n = axis["points"] * size
        a = s[off:off + n]
        if len(a) != n or t[off + delta:off + delta + n] != a:
            return False
    return True


def _rebase(src: dict[str, Any], src_revision: int, method: str, delta: int, source: FirmwareRecord,
            target: FirmwareRecord, t: bytes, now: str) -> dict[str, Any]:
    r = copy.deepcopy(src)
    for key in [k for k in r if k.startswith("x_")]:
        del r[key]
    if delta:
        _shift(r, delta)
    off, end = r["file_offset"], r["end_file_offset"]
    if method in ("axes_match", "same_layout"):
        new = t[off:off + len(from_hex(src["original_bytes"]))]
        r["original_bytes"] = to_hex(new)
        if "original_raw_bytes" in r:
            r["original_raw_bytes"] = to_hex(new)
        values = _physical_values(r, new)
        if values is None:
            r.pop("original_physical_values", None)
        else:
            r["original_physical_values"] = values
        r["proposed_bytes"] = None
        r["proposed_physical_values"] = None
        for axis in r.get("axes", []):
            if axis.get("source") == "stored" and axis.get("file_offset") is not None:
                axis["values"] = _axis_values(axis, t)

    concept = re.sub(r"[^A-Za-z0-9_.]", "_", str(src[CONCEPT_FIELD[src["category"]]]))
    confidence, step = METHODS[method]
    shift = f" shifted by {delta:+d} bytes" if delta else ""
    r.update({
        "record_id": f"xfer-{target.blob.sha256[:12]}-{off:X}-{concept}"[:128],
        "revision": 1, "review_state": "draft", "reviewer": None, "created_at": now, "updated_at": now,
        "sha256": target.blob.sha256, "md5": target.blob.md5, "file_size": target.blob.size,
        "software_id": target.software_id, "calibration_id": target.calibration_id,
        "ecu_vendor": target.ecu_vendor or src.get("ecu_vendor"),
        "ecu_family": target.ecu_family or src["ecu_family"],
        "processor": target.processor or src.get("processor"),
        "confidence": min(float(src.get("confidence", 1.0)), confidence),
        "evidence": [
            {"source_type": "aktool_json", "source_ref": f"{src['record_id']}@r{src_revision}",
             "claim": f"approved on firmware {source.blob.sha256[:12]} at 0x{src['file_offset']:X}{shift}",
             "file_offset": off, "verified_against_bin": False},
            {"source_type": "binary_check", "source_ref": target.blob.sha256,
             "claim": f"{step}; {end - off} bytes at 0x{off:X} checked against this BIN",
             "file_offset": off, "verified_against_bin": True},
        ],
        "provenance": [{"source_type": "aktool_transfer", "source_name": f"{src['record_id']}@r{src_revision}",
                        "sha256": source.blob.sha256, "license": None, "imported_at": now}],
        "validation_steps": ["transferred from an approved record", step, "needs human review"],
        "x_transfer": {"method": method, "delta": delta, "source_record_id": src["record_id"],
                       "source_revision": src_revision, "source_sha256": source.blob.sha256},
    })
    return r


def _same_offset_ratio(session: Session, a: FirmwareRecord, b: FirmwareRecord) -> float:
    fa, fb = session.get(FirmwareFingerprint, a.blob_id), session.get(FirmwareFingerprint, b.blob_id)
    if fa is None or fb is None:
        return 0.0
    ha, hb = fa.blocks.split(","), fb.blocks.split(",")
    informative = [h for h in ha if h]
    same = sum(1 for x, y in zip(ha, hb) if x and x == y)
    return same / len(informative) if informative else 0.0


def _shift(node: Any, delta: int) -> None:
    """Move every file offset by delta; ECU addresses no longer hold once bytes moved, so they are cleared."""
    if isinstance(node, list):
        for v in node:
            _shift(v, delta)
    elif isinstance(node, dict):
        for k, v in node.items():
            if k.endswith("file_offset") and isinstance(v, int):
                node[k] = v + delta
            elif k.endswith("ecu_address"):
                node[k] = None
            else:
                _shift(v, delta)


def _physical_values(r: dict[str, Any], raw_bytes: bytes) -> list[list[float]] | None:
    try:
        code, signed = ols_json._code_for(r["data_type"])
        factor, offset, reciprocal = ols_json._formula_parts(r["formula"])
    except (ValueError, KeyError):
        return None
    rows, columns = r["rows"], r["columns"]
    raw = ols_json._decode(raw_bytes, code, _TYPE_SIZES[r["data_type"]], r["byte_order"], signed, rows * columns)
    phys = [ols_json._phys(v, factor, offset, reciprocal) for v in raw]
    if r.get("storage_order") == "column_major":
        return [[phys[c * rows + row] for c in range(columns)] for row in range(rows)]
    return [phys[row * columns:(row + 1) * columns] for row in range(rows)]


def _axis_values(axis: dict[str, Any], t: bytes) -> list[float] | None:
    try:
        code, signed = ols_json._code_for(axis["data_type"])
        factor, offset, reciprocal = ols_json._formula_parts(axis.get("formula") or {"type": "identity"})
    except (ValueError, KeyError):
        return None
    size, off, points = _TYPE_SIZES[axis["data_type"]], axis["file_offset"], axis["points"]
    raw = t[off:off + points * size]
    if len(raw) != points * size:
        return None
    return [ols_json._phys(v, factor, offset, reciprocal)
            for v in ols_json._decode(raw, code, size, axis.get("byte_order", "little"), signed, points)]
