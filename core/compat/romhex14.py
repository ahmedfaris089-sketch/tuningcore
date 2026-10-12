"""romHEX14 cloud API engine backed by approved AKTOOL knowledge.

romHEX14 (src/cloud/CloudClient.cpp) talks to a user-configurable server through /v1/health,
/v1/dtc/analyze, /v1/dtc/disable, /v1/features/detect and /v1/features/apply. This engine answers those
calls from approved or validated records made for the exact same BIN (same SHA-256), rechecked against
the uploaded bytes. A file we have no approved knowledge for gets an empty answer, never a guess.

A modified BIN is only returned when every write is backed by an approved record, the bytes at each
offset still equal the record's original bytes, and the family checksum can be handled.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core import audit, firmware
from core.checksum import ChecksumRegistry
from core.db import Definition, FirmwareRecord
from core.errors import AktoolError
from core.hexbytes import from_hex
from core.jsonfactory import TRUSTED_STATES
from core.settings import Settings
from core.validators import check_against_bin
from core.vault import BinVault

DTC_CATEGORIES = ("bosch_dtc", "non_bosch_dtc")
OBD_CODE = re.compile(r"^[PBCU][0-9A-F]{4}$")
UPLOAD_NAME = "romhex14-upload.bin"


class CompatError(Exception):
    """An error in romHEX14's wire shape: {"ok": false, "error": ..., "code": ..., "detail": ...}."""

    def __init__(self, status_code: int, error: str, code: str, detail: Any = None):
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.code = code
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"ok": False, "error": self.error, "code": self.code}
        if self.detail is not None:
            body["detail"] = self.detail
        return body


@dataclass
class Write:
    offset: int
    original: bytes
    new: bytes
    record: dict[str, Any]


@dataclass
class Patched:
    data: bytes
    family: str
    checksum: str  # "corrected" or "not_corrected"
    firmware_id: int
    record_ids: list[str] = field(default_factory=list)


class Rx14Engine:
    def __init__(self, settings: Settings, vault: BinVault, checksums: ChecksumRegistry):
        self.settings = settings
        self.vault = vault
        self.checksums = checksums

    # ---- read-only calls -----------------------------------------------------------------------
    def analyze(self, session: Session, rom: bytes, family: str | None, actor: str) -> dict[str, Any]:
        fw = self._ingest(session, rom, family, actor)
        records, skipped = self._trusted(session, rom, DTC_CATEGORIES)
        dtcs = []
        for idx, rec in enumerate(records):
            code = str(rec["dtc_code"]).strip().upper()
            dtcs.append({"idx": idx, "code": code, "obd": code if OBD_CODE.match(code) else "", "man": "",
                         "status": _dtc_status(rec, rom), "info": rec["name"], "record_id": rec["record_id"],
                         "revision": rec["revision"], "can_disable": bool(rec.get("proposed_bytes"))})
        return {"ok": True, "fid": fw.blob.sha256, "firmware_id": fw.id,
                "ecu": {"name": _ecu_name(fw), "match": self._match(session, fw.blob.sha256)},
                "dtcs_total": len(dtcs), "dtcs_on": sum(d["status"] == "ON" for d in dtcs),
                "dtcs_off": sum(d["status"] == "OFF" for d in dtcs), "dtcs": dtcs, "skipped": skipped,
                "family_hint": family}

    def detect_features(self, session: Session, rom: bytes, family: str | None, actor: str) -> dict[str, Any]:
        self._ingest(session, rom, family, actor)
        records, skipped = self._trusted(session, rom, ("function_on_off",))
        available: dict[str, Any] = {}
        unavailable: dict[str, str] = {}
        for key, group in _group_features(records).items():
            missing = [r["record_id"] for r in group if r.get("proposed_state") not in ("on", "off")]
            if missing:
                unavailable[key] = f"no proposed_state on {', '.join(missing)}"
                continue
            available[key] = {"label": group[0]["name"], "dtc_count": 0, "has_map_mods": False,
                              "has_patches": True, "state": group[0]["proposed_state"],
                              "records": [r["record_id"] for r in group]}
        return {"ok": True, "available": available, "unavailable": unavailable, "skipped": skipped}

    # ---- calls that return a modified BIN --------------------------------------------------------
    def disable_dtcs(self, session: Session, rom: bytes, codes: list[str], family: str | None,
                     actor: str) -> Patched:
        records, _ = self._trusted(session, rom, DTC_CATEGORIES)
        lookup: dict[str, dict[str, Any]] = {}
        for idx, rec in enumerate(records):
            for key in (str(rec["dtc_code"]).strip().upper(), rec["record_id"], str(idx)):
                lookup.setdefault(key, rec)
        writes = []
        for code in codes:
            rec = lookup.get(code.strip().upper()) or lookup.get(code.strip())
            if rec is None:
                raise CompatError(422, f"{code}: no approved record for this exact file", "DTC_NOT_KNOWN",
                                  {"code": code})
            if not rec.get("proposed_bytes"):
                raise CompatError(422, f"{code}: approved record has no proposed_bytes", "NO_PROPOSED_BYTES",
                                  {"code": code, "record_id": rec["record_id"]})
            writes.append(Write(rec["file_offset"], from_hex(rec["original_bytes"]), from_hex(rec["proposed_bytes"]),
                                rec))
        return self._patch(session, rom, writes, family, actor, "romhex14.dtc_disable")

    def apply_features(self, session: Session, rom: bytes, features: list[str], family: str | None,
                       actor: str) -> Patched:
        records, _ = self._trusted(session, rom, ("function_on_off",))
        groups = _group_features(records)
        writes = []
        for key in features:
            group = groups.get(key.strip())
            if not group:
                raise CompatError(422, f"{key}: no approved function for this exact file", "FEATURE_NOT_KNOWN",
                                  {"feature": key})
            for rec in group:
                state = rec.get("proposed_state")
                if state not in ("on", "off"):
                    raise CompatError(422, f"{key}: {rec['record_id']} has no proposed_state", "NO_PROPOSED_STATE",
                                      {"feature": key, "record_id": rec["record_id"]})
                target = rec["on_bytes"] if state == "on" else rec["off_bytes"]
                writes.append(Write(rec["file_offset"], from_hex(rec["original_bytes"]), from_hex(target), rec))
        return self._patch(session, rom, writes, family, actor, "romhex14.features_apply")

    # ---- helpers --------------------------------------------------------------------------------
    def _trusted(self, session: Session, rom: bytes,
                 categories: tuple[str, ...]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Latest revisions that are approved/validated and still match the uploaded bytes."""
        sha = hashlib.sha256(rom).hexdigest()
        defs = session.scalars(select(Definition).where(Definition.sha256 == sha,
                                                        Definition.category.in_(categories)).order_by(Definition.id))
        records, skipped = [], []
        for d in defs:
            rev = d.revisions[-1]
            if rev.review_state not in TRUSTED_STATES or not rev.binary_verified:
                continue
            rec = json.loads(rev.payload)
            errors = [i for i in check_against_bin(rec, rom) if i.severity == "error"]
            if errors:
                skipped.append({"record_id": d.record_id, "codes": sorted({i.code for i in errors})})
                continue
            records.append(rec)
        return records, skipped

    def _match(self, session: Session, sha: str) -> str:
        known = session.scalar(select(Definition.id).where(Definition.sha256 == sha).limit(1))
        return "exact" if known is not None else "unknown"

    def _ingest(self, session: Session, data: bytes, family: str | None, actor: str,
                role: str = "unknown", name: str = UPLOAD_NAME) -> FirmwareRecord:
        try:
            rec, _ = firmware.ingest(session, self.vault, data, name, actor,
                                     {"ecu_family": family, "file_role": role})
        except AktoolError as exc:
            raise CompatError(exc.status_code, exc.message, exc.code) from exc
        return rec

    def _patch(self, session: Session, rom: bytes, writes: list[Write], family_hint: str | None, actor: str,
               action: str) -> Patched:
        families = {str(w.record["ecu_family"]) for w in writes}
        if len(families) != 1:
            raise CompatError(422, "selected records belong to different ECU families", "MIXED_FAMILIES",
                              {"families": sorted(families)})
        family = families.pop()
        data = bytearray(rom)
        taken: dict[int, int] = {}
        for w in sorted(writes, key=lambda w: w.offset):
            if len(w.new) != len(w.original):
                raise CompatError(422, f"{w.record['record_id']}: new bytes and original bytes differ in length",
                                  "LENGTH_MISMATCH", {"record_id": w.record["record_id"]})
            if bytes(rom[w.offset:w.offset + len(w.original)]) != w.original:
                raise CompatError(422, f"{w.record['record_id']}: bytes at offset differ from the record",
                                  "ORIGINAL_BYTES_MISMATCH", {"record_id": w.record["record_id"]})
            for i, b in enumerate(w.new):
                pos = w.offset + i
                if pos in taken and taken[pos] != b:
                    raise CompatError(422, "two selected records write different bytes to the same offset",
                                      "OVERLAPPING_WRITES", {"offset": pos})
                taken[pos] = b
                data[pos] = b

        corrector = self.checksums.get(family)
        if corrector is not None:
            patched, checksum = corrector(bytes(data)), "corrected"
        elif self.settings.rx14_checksum == "client":
            patched, checksum = bytes(data), "not_corrected"
        else:
            raise CompatError(422, f"no checksum corrector for ECU family '{family}', so no modified file is "
                                   "returned. Set AKTOOL_RX14_CHECKSUM=client to correct it in romHEX14 instead.",
                              "CHECKSUM_UNAVAILABLE", {"family": family})
        if len(patched) != len(rom):
            raise CompatError(500, "checksum corrector changed the file size", "CHECKSUM_SIZE_CHANGED")

        source = self._ingest(session, rom, family_hint, actor)
        out = source
        if patched != rom:
            out = self._ingest(session, patched, family, actor, role="modified", name=f"{action}.bin")
            if out.id != source.id:
                firmware.add_relation(session, out.id, source.id, "modified_from", actor, source=action)
        record_ids = sorted({w.record["record_id"] for w in writes})
        audit.record(session, actor, action, "firmware", out.id, source_firmware_id=source.id, records=record_ids,
                     family=family, checksum=checksum)
        session.commit()
        return Patched(patched, family, checksum, out.id, record_ids)


def _dtc_status(rec: dict[str, Any], rom: bytes) -> str:
    original = from_hex(rec["original_bytes"])
    current = rom[rec["file_offset"]:rec["file_offset"] + len(original)]
    proposed = rec.get("proposed_bytes")
    if proposed and current == from_hex(proposed):
        return "OFF"
    return "ON" if current == original else "UNKNOWN"


def _group_features(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        groups.setdefault(str(rec["function_key"]), []).append(rec)
    return groups


def _ecu_name(fw: FirmwareRecord) -> str:
    return fw.ecu_label or " ".join(p for p in (fw.ecu_family, fw.software_id) if p) or ""
