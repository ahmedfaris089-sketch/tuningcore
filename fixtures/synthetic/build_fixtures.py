"""Builds a SYNTHETIC 64 KiB BIN plus matching example records for each JSON type.

Nothing here comes from a real ECU. It exists so schemas, validators and round-trip tests have
deterministic bytes to check against. Run from the repo root: python -m fixtures.synthetic.build_fixtures
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN_PATH = ROOT / "fixtures" / "synthetic" / "synthetic_ecu.bin"
VALID = ROOT / "schemas" / "examples" / "valid"
INVALID = ROOT / "schemas" / "examples" / "invalid"

SIZE = 0x10000
SW_ID, CAL_ID = "SYN0001", "CAL0001"
OFF_SWITCH = 0x1000
OFF_AXIS_X, OFF_AXIS_Y, OFF_MAP = 0x1F00, 0x1F10, 0x2000
OFF_MASK, OFF_PATH, OFF_GM = 0x3000, 0x3100, 0x4000
TS = "2026-10-11T00:00:00Z"


def build_bin() -> bytes:
    buf = bytearray((i * 7 + 3) & 0xFF for i in range(SIZE))
    ident = f"SWID={SW_ID};CALID={CAL_ID};".encode()
    buf[0x100:0x100 + len(ident)] = ident
    buf[OFF_SWITCH] = 0x01
    for i, v in enumerate([800, 1600, 2400, 3200]):
        struct.pack_into(">H", buf, OFF_AXIS_X + 2 * i, v)
    for i, v in enumerate([10, 20, 30, 40]):
        struct.pack_into(">H", buf, OFF_AXIS_Y + 2 * i, v)
    for i in range(16):
        struct.pack_into(">H", buf, OFF_MAP + 2 * i, 1000 + 10 * i)
    struct.pack_into(">H", buf, OFF_MASK + 2 * 5, 0x00FF)
    struct.pack_into(">H", buf, OFF_PATH + 2 * 5, 0x0042)
    buf[OFF_GM:OFF_GM + 4] = bytes([0x04, 0x20, 0x01, 0x00])
    return bytes(buf)


def hx(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def header(data: bytes, category: str, name: str, start: int, end: int, byte_order: str) -> dict:
    return {
        "schema_version": "1.0.0",
        "record_id": f"syn-{category}-0001",
        "revision": 1,
        "category": category,
        "name": name,
        "description": "Synthetic example for schema and validator tests.",
        "software_id": SW_ID,
        "calibration_id": CAL_ID,
        "ecu_vendor": "Synthetic",
        "ecu_family": "synthetic_test",
        "processor": None,
        "file_size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_offset": start,
        "ecu_address": None,
        "end_file_offset": end,
        "byte_order": byte_order,
        "original_bytes": hx(data[start:end]),
        "evidence": [{"source_type": "manual", "source_ref": "fixtures/synthetic/build_fixtures.py",
                      "claim": "Bytes written at this offset by the fixture builder.", "file_offset": start,
                      "verified_against_bin": True}],
        "confidence": 1.0,
        "review_state": "approved",
        "reviewer": "fixture-builder",
        "created_at": TS,
        "updated_at": TS,
        "provenance": [{"source_type": "manual", "source_name": "synthetic fixture builder", "sha256": None,
                        "license": "test-only", "imported_at": TS}],
        "validation_steps": ["schema", "binary original_bytes check"],
    }


def entry(data: bytes, base: int, index: int, size: int, relation: str, **extra) -> dict:
    off = base + index * size
    e = {"table_base_file_offset": base, "table_base_ecu_address": None, "entry_index": index,
         "entry_file_offset": off, "entry_ecu_address": None, "entry_size": size,
         "original_bytes": hx(data[off:off + size]), "decoded_value": int.from_bytes(data[off:off + size], "big"),
         "relation_to_dtc": relation,
         "evidence": [{"source_type": "manual", "claim": "Fixture builder wrote this entry.",
                       "file_offset": off, "verified_against_bin": True}]}
    e.update(extra)
    return e


def records(data: bytes) -> dict[str, dict]:
    on_off = header(data, "function_on_off", "Synthetic fan switch", OFF_SWITCH, OFF_SWITCH + 1, "not_applicable")
    on_off.update({"function_key": "synthetic_fan", "switch_style": "single_value", "data_type": "uint8",
                   "data_width_bits": 8, "original_value": 1, "on_value": 1, "off_value": 0,
                   "on_bytes": "01", "off_bytes": "00", "bit_mask": None, "bit_position": None,
                   "logic_description": "1 enables the synthetic fan function, 0 disables it.",
                   "dependencies": [], "proposed_state": None})

    m = header(data, "function_map_table", "Synthetic torque limit", OFF_MAP, OFF_MAP + 32, "big")
    raw = [struct.unpack_from(">H", data, OFF_MAP + 2 * i)[0] for i in range(16)]
    m.update({"map_key": "syn_torque_limit", "shape": "map", "data_type": "uint16", "rows": 4, "columns": 4,
              "storage_order": "row_major", "formula": {"type": "linear", "factor": 0.1, "offset": 0.0, "rounding": "none"},
              "unit": "Nm",
              "axes": [
                  {"name": "engine speed", "kind": "x", "points": 4, "source": "stored", "file_offset": OFF_AXIS_X,
                   "ecu_address": None, "data_type": "uint16", "byte_order": "big",
                   "formula": {"type": "identity"}, "unit": "rpm", "values": [800, 1600, 2400, 3200]},
                  {"name": "pedal", "kind": "y", "points": 4, "source": "stored", "file_offset": OFF_AXIS_Y,
                   "ecu_address": None, "data_type": "uint16", "byte_order": "big",
                   "formula": {"type": "identity"}, "unit": "%", "values": [10, 20, 30, 40]}],
              "original_raw_bytes": hx(data[OFF_MAP:OFF_MAP + 32]),
              "original_physical_values": [[round(v * 0.1, 4) for v in raw[r * 4:(r + 1) * 4]] for r in range(4)],
              "proposed_physical_values": None, "proposed_bytes": None,
              "physical_limits": {"min": 0, "max": 6553.5}, "raw_limits": {"min": 0, "max": 65535},
              "related_functions": []})

    b = header(data, "bosch_dtc", "Synthetic Bosch DTC P0123", OFF_MASK + 10, OFF_MASK + 12, "big")
    b.update({"dtc_code": "P0123", "encoding_profile": "synthetic_bosch_v1", "dtc_record_index": 5,
              "start_file_offset": OFF_MASK + 10,
              "mask_table": [entry(data, OFF_MASK, 5, 2, "mask word for record 5", bit_meaning="0x00FF = all bits enabled")],
              "error_path_table": [entry(data, OFF_PATH, 5, 2, "error path id for record 5", value_meaning="path 0x42")],
              "relationship_validation": {"status": "verified", "notes": "Same record index in both tables."},
              "proposed_strategy": None, "proposed_bytes": None})

    n = header(data, "non_bosch_dtc", "Synthetic non-Bosch DTC P0420", OFF_GM, OFF_GM + 4, "big")
    n.update({"dtc_code": "P0420", "ecu_family_profile": {"key": "synthetic_gm_like", "version": "1"},
              "encoding_profile": "synthetic_code_status_v1", "record_index": 0,
              "tables": [entry(data, OFF_GM, 0, 2, "DTC code bytes", table_type="code"),
                         {**entry(data, OFF_GM + 2, 0, 2, "status/enable byte pair"), "table_type": "enable"}],
              "disable_strategy": None, "relationships": ["code entry 0 pairs with enable entry 0"],
              "proposed_bytes": None})
    return {"function_on_off": on_off, "function_map_table": m, "bosch_dtc": b, "non_bosch_dtc": n}


def invalid_cases(valid: dict[str, dict]) -> dict[str, dict]:
    """Each case names the error code the validators must raise."""
    cases = {}

    def mutate(name: str, base: str, expect: str, fn) -> None:
        r = copy.deepcopy(valid[base])
        fn(r)
        r["x_expected_error"] = expect
        cases[name] = r

    mutate("wrong_original_bytes", "function_on_off", "ORIGINAL_BYTES_MISMATCH", lambda r: r.update(original_bytes="02", on_bytes="01", off_bytes="00"))
    mutate("offset_past_end", "function_on_off", "OFFSET_OUT_OF_RANGE", lambda r: r.update(file_offset=SIZE - 1, end_file_offset=SIZE + 1, original_bytes="00 00", on_bytes="00 01", off_bytes="00 00"))
    mutate("missing_evidence", "function_on_off", "SCHEMA_VIOLATION", lambda r: r.update(evidence=[]))
    mutate("approved_without_reviewer", "bosch_dtc", "SCHEMA_VIOLATION", lambda r: r.update(reviewer=None))
    mutate("map_size_mismatch", "function_map_table", "MAP_SIZE_MISMATCH", lambda r: r.update(rows=3))
    mutate("bad_hex", "bosch_dtc", "SCHEMA_VIOLATION", lambda r: r.update(original_bytes="00ff"))
    mutate("code_patch_validated", "function_on_off", "SCHEMA_VIOLATION", lambda r: r.update(switch_style="code_patch", review_state="validated"))
    mutate("unknown_field", "non_bosch_dtc", "SCHEMA_VIOLATION", lambda r: r.update(auto_apply=True))
    return cases


def main() -> None:
    data = build_bin()
    BIN_PATH.write_bytes(data)
    valid = records(data)
    for d in (VALID, INVALID):
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("*.json"):
            old.unlink()
    for cat, rec in valid.items():
        (VALID / f"{cat}.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for name, rec in invalid_cases(valid).items():
        (INVALID / f"{name}.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {BIN_PATH.relative_to(ROOT)} and {len(valid)} valid / {len(invalid_cases(valid))} invalid examples")


if __name__ == "__main__":
    main()
