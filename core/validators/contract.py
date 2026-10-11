"""Schema validation for the four AKTOOL record types, plus semantic checks JSON Schema cannot express."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from core.hexbytes import from_hex

CATEGORIES = ("function_on_off", "function_map_table", "bosch_dtc", "non_bosch_dtc")

_DATA_TYPE_BYTES = {"uint8": 1, "int8": 1, "uint16": 2, "int16": 2, "uint32": 4, "int32": 4,
                    "float32": 4, "float64": 8}


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class ContractValidator:
    def __init__(self, schema_dir: Path):
        resources = []
        self._by_category: dict[str, dict[str, Any]] = {}
        for path in sorted(Path(schema_dir).glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            resources.append((schema["$id"], Resource.from_contents(schema)))
            name = path.name.removesuffix(".schema.json")
            if name in CATEGORIES:
                self._by_category[name] = schema
        missing = set(CATEGORIES) - set(self._by_category)
        if missing:
            raise RuntimeError(f"missing schemas for: {sorted(missing)}")
        self._registry = Registry().with_resources(resources)

    def validate(self, record: Any) -> list[Issue]:
        if not isinstance(record, dict):
            return [Issue("error", "NOT_AN_OBJECT", "$", "record must be a JSON object")]
        category = record.get("category")
        if category not in self._by_category:
            return [Issue("error", "UNKNOWN_CATEGORY", "$.category", f"category must be one of {list(CATEGORIES)}")]
        validator = Draft202012Validator(self._by_category[category], registry=self._registry)
        issues = [
            Issue("error", "SCHEMA_VIOLATION", _json_path(err.absolute_path), err.message)
            for err in sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
        ]
        if not issues:
            issues.extend(_semantic_checks(record))
        return issues


def _json_path(parts) -> str:
    out = "$"
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


def _semantic_checks(r: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []

    def err(code: str, path: str, msg: str) -> None:
        issues.append(Issue("error", code, path, msg))

    def warn(code: str, path: str, msg: str) -> None:
        issues.append(Issue("warning", code, path, msg))

    start, end, size = r["file_offset"], r["end_file_offset"], r["file_size"]
    if end <= start:
        err("EMPTY_OR_REVERSED_RANGE", "$.end_file_offset", "end_file_offset must be greater than file_offset (exclusive end)")
    if end > size:
        err("OFFSET_OUT_OF_RANGE", "$.end_file_offset", f"end_file_offset {end} exceeds file_size {size}")

    original = from_hex(r["original_bytes"])
    if end > start and len(original) != end - start:
        err("ORIGINAL_BYTES_LENGTH", "$.original_bytes",
            f"original_bytes has {len(original)} bytes but the range is {end - start}")

    if datetime.fromisoformat(r["updated_at"].replace("Z", "+00:00")) < datetime.fromisoformat(
            r["created_at"].replace("Z", "+00:00")):
        err("TIME_ORDER", "$.updated_at", "updated_at is earlier than created_at")

    if r["software_id"] is None or r["calibration_id"] is None:
        warn("ID_MISSING", "$.software_id", "software_id or calibration_id is null; final export needs a documented exception")

    if not any(e.get("verified_against_bin") for e in r["evidence"]):
        warn("NO_BIN_EVIDENCE", "$.evidence", "no evidence item is marked verified_against_bin")

    category = r["category"]
    if category == "function_on_off":
        on_b, off_b = from_hex(r["on_bytes"]), from_hex(r["off_bytes"])
        if len(on_b) != len(original) or len(off_b) != len(original):
            err("SWITCH_BYTES_LENGTH", "$.on_bytes", "on_bytes and off_bytes must have the same length as original_bytes")
        if original not in (on_b, off_b):
            warn("ORIGINAL_NOT_ON_OR_OFF", "$.original_bytes", "original_bytes equals neither on_bytes nor off_bytes")
    elif category == "function_map_table":
        issues.extend(_map_checks(r, end - start))
    elif category == "bosch_dtc":
        for table in ("mask_table", "error_path_table"):
            issues.extend(_entry_checks(r, r[table], f"$.{table}"))
        if r["relationship_validation"]["status"] != "verified" and r["review_state"] == "validated":
            err("DTC_RELATION_UNVERIFIED", "$.relationship_validation",
                "a validated Bosch DTC needs relationship_validation.status == 'verified'")
        if "start_file_offset" in r and r["start_file_offset"] != start:
            warn("DTC_START_MISMATCH", "$.start_file_offset", "start_file_offset differs from file_offset")
    elif category == "non_bosch_dtc":
        issues.extend(_entry_checks(r, r["tables"], "$.tables"))
    return issues


def _map_checks(r: dict[str, Any], region_len: int) -> list[Issue]:
    issues: list[Issue] = []
    width = _DATA_TYPE_BYTES.get(r["data_type"])
    cells = r["rows"] * r["columns"]
    for d in r.get("extra_dimensions", []):
        cells *= d
    shape_rules = {"scalar": cells == 1, "curve": r["rows"] == 1 or r["columns"] == 1}
    if r["shape"] in shape_rules and not shape_rules[r["shape"]]:
        issues.append(Issue("error", "SHAPE_DIMENSIONS", "$.shape", f"shape {r['shape']} does not match rows x columns"))
    if width is None:
        issues.append(Issue("error", "MAP_DATA_TYPE", "$.data_type", "map data_type must be a byte-sized numeric type"))
        return issues
    if r["byte_order"] == "not_applicable" and width > 1:
        issues.append(Issue("error", "BYTE_ORDER_REQUIRED", "$.byte_order", "multi-byte map values need little or big byte_order"))
    if cells * width != region_len:
        issues.append(Issue("error", "MAP_SIZE_MISMATCH", "$.end_file_offset",
                            f"{cells} cells x {width} bytes = {cells * width}, but the range is {region_len} bytes"))
    phys = r.get("original_physical_values")
    if phys is not None:
        flat = [v for row in phys for v in row]
        if len(flat) != cells or len(phys) != r["rows"]:
            issues.append(Issue("error", "PHYSICAL_VALUES_SHAPE", "$.original_physical_values",
                                "original_physical_values must be rows x columns"))
    for i, axis in enumerate(r["axes"]):
        values = axis.get("values")
        if values and any(b <= a for a, b in zip(values, values[1:])) and any(b >= a for a, b in zip(values, values[1:])):
            issues.append(Issue("warning", "AXIS_NOT_MONOTONIC", f"$.axes[{i}].values", "axis values are not strictly monotonic"))
        if values is not None and len(values) != axis["points"]:
            issues.append(Issue("error", "AXIS_POINTS", f"$.axes[{i}].values", "len(values) must equal points"))
    expected = {"x": r["columns"], "y": r["rows"]}
    for i, axis in enumerate(r["axes"]):
        want = expected.get(axis["kind"])
        if want is not None and r["shape"] in ("map",) and axis["points"] != want:
            issues.append(Issue("error", "AXIS_POINTS_VS_SHAPE", f"$.axes[{i}].points",
                                f"{axis['kind']} axis has {axis['points']} points but the map needs {want}"))
    return issues


def _entry_checks(r: dict[str, Any], entries: list[dict[str, Any]], base: str) -> list[Issue]:
    issues: list[Issue] = []
    for i, e in enumerate(entries):
        b = from_hex(e["original_bytes"])
        if len(b) != e["entry_size"]:
            issues.append(Issue("error", "ENTRY_BYTES_LENGTH", f"{base}[{i}].original_bytes",
                                f"original_bytes has {len(b)} bytes but entry_size is {e['entry_size']}"))
        if e["entry_file_offset"] + e["entry_size"] > r["file_size"]:
            issues.append(Issue("error", "OFFSET_OUT_OF_RANGE", f"{base}[{i}].entry_file_offset", "entry extends past file_size"))
        if e["entry_file_offset"] < e["table_base_file_offset"]:
            issues.append(Issue("error", "ENTRY_BEFORE_TABLE", f"{base}[{i}].entry_file_offset",
                                "entry_file_offset is before table_base_file_offset"))
    return issues
