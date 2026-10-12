"""OLS map-pack JSON (WinOLS "OLS-Files" export) importer and exporter.

Document shape: {"maps": [{"Name": ..., "Fieldvalues.StartAddr": "$39C818", ...}, ...]} where every
value is a string. Format facts this module relies on:

* Addresses are file offsets written as "$" + hex, or "0" when unset.
* Decimals use the exporting machine's locale: "0,046882" and "0.046882" both occur.
* Type: eEinzel (1x1 value), eEindim (1xN curve), eZweidim (rows x columns map),
  eZweiInv (Nx1 curve laid out vertically).
* DataOrg: eByte, eLoHi / eHiLo (16-bit), eLoHiLoHi / eHiLoHiLo (32-bit),
  eFloatLoHi / eFloatHiLo (float32), eDoubleLoHi / eDoubleHiLo (float64). "LoHi" = little endian.
* Columns = X axis points, Rows = Y axis points.
* Axis DataSrc: eRom (points stored at AxisX.DataAddr) or eUserdef (AxisX.Values, space separated).

Nothing is dropped silently: every map is either turned into a draft function_map_table record or
reported in `skipped` with a reason code. Each record keeps the source map under `x_ols_source` so
an export reproduces the original properties.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.hexbytes import to_hex

FORMAT_NAME = "ols_mappack_json"

# Alternative spellings seen across WinOLS versions/locales -> canonical key. Extendable per call.
DEFAULT_ALIASES: dict[str, str] = {
    "Adresse": "Fieldvalues.StartAddr",
    "StartAddr": "Fieldvalues.StartAddr",
    "Address": "Fieldvalues.StartAddr",
    "Spalten": "Columns",
    "Zeilen": "Rows",
    "Faktor": "Fieldvalues.Factor",
    "Factor": "Fieldvalues.Factor",
    "Einheit": "Fieldvalues.Unit",
    "Unit": "Fieldvalues.Unit",
    "Datenorganisation": "DataOrg",
    "Typ": "Type",
    "Kommentar": "Comment",
    "Ordner": "FolderName",
}

# DataOrg -> (struct code without sign, size, byte order, is_float)
DATA_ORG: dict[str, tuple[str, int, str, bool]] = {
    "eByte": ("B", 1, "not_applicable", False),
    "eLoHi": ("H", 2, "little", False),
    "eHiLo": ("H", 2, "big", False),
    "eLoHiLoHi": ("I", 4, "little", False),
    "eHiLoHiLo": ("I", 4, "big", False),
    "eFloatLoHi": ("f", 4, "little", True),
    "eFloatHiLo": ("f", 4, "big", True),
    "eDoubleLoHi": ("d", 8, "little", True),
    "eDoubleHiLo": ("d", 8, "big", True),
}
_TYPE_NAMES = {("B", False): "uint8", ("B", True): "int8", ("H", False): "uint16", ("H", True): "int16",
               ("I", False): "uint32", ("I", True): "int32", ("f", False): "float32", ("f", True): "float32",
               ("d", False): "float64", ("d", True): "float64"}
_DATA_ORG_BY_TYPE = {(v[0], v[2]): k for k, v in DATA_ORG.items()}

SHAPES = {"eEinzel": "scalar", "eEindim": "curve", "eZweidim": "map", "eZweiInv": "curve"}


@dataclass
class Skip:
    index: int
    name: str
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name, "code": self.code, "message": self.message}


@dataclass
class ImportReport:
    records: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    total_maps: int = 0

    def summary(self) -> dict[str, Any]:
        return {"format": FORMAT_NAME, "total_maps": self.total_maps, "proposed": len(self.records),
                "skipped": len(self.skipped), "skipped_items": [s.to_dict() for s in self.skipped],
                "warnings": self.warnings}


class OlsFormatError(ValueError):
    pass


def looks_like_ols_json(doc: Any) -> bool:
    if not isinstance(doc, dict) or not isinstance(doc.get("maps"), list):
        return False
    return all(isinstance(m, dict) for m in doc["maps"]) and (
        not doc["maps"] or any(_has_ols_keys(m) for m in doc["maps"]))


def _has_ols_keys(m: dict[str, Any]) -> bool:
    return any(k.startswith(("Fieldvalues.", "AxisX.", "AxisY.")) or k in ("DataOrg", "Type") for k in m)


def parse_number(text: Any) -> float:
    if isinstance(text, (int, float)):
        return float(text)
    s = str(text).strip()
    if s.count(",") == 1 and "." not in s:
        s = s.replace(",", ".")
    return float(s)


def parse_address(text: Any) -> int | None:
    s = str(text).strip()
    if s in ("", "0"):
        return None
    if s.startswith("$"):
        return int(s[1:], 16)
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def format_number(value: float, decimal_comma: bool) -> str:
    text = f"{value:.6f}"
    return text.replace(".", ",") if decimal_comma else text


def apply_aliases(m: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    out = dict(m)
    for alt, canonical in aliases.items():
        if alt in out and canonical not in out:
            out[canonical] = out.pop(alt)
    return out


def import_document(doc: Any, bin_data: bytes, firmware: dict[str, Any],
                    aliases: dict[str, str] | None = None, source_name: str = "ols.json") -> ImportReport:
    """Turn every map of an OLS JSON document into a draft function_map_table record.

    `firmware` carries sha256, md5, file_size, software_id, calibration_id, ecu_vendor, ecu_family.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("maps"), list):
        raise OlsFormatError("not an OLS map-pack JSON document: expected a top-level 'maps' array")
    alias_map = {**DEFAULT_ALIASES, **(aliases or {})}
    report = ImportReport(total_maps=len(doc["maps"]))
    source_sha = hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    seen: dict[tuple[int, int], str] = {}
    for index, raw_map in enumerate(doc["maps"]):
        name = str(raw_map.get("Name") or raw_map.get("IdName") or f"map #{index}") if isinstance(raw_map, dict) else f"map #{index}"
        if not isinstance(raw_map, dict):
            report.skipped.append(Skip(index, name, "NOT_AN_OBJECT", "map entry is not a JSON object"))
            continue
        m = apply_aliases(raw_map, alias_map)
        try:
            record, warns = _map_to_record(index, m, raw_map, bin_data, firmware, source_name, source_sha, now)
        except _SkipMap as skip:
            report.skipped.append(Skip(index, name, skip.code, str(skip)))
            continue
        key = (record["file_offset"], record["end_file_offset"])
        if key in seen:
            warns.append(f"same range as '{seen[key]}'")
        seen.setdefault(key, record["name"])
        for w in warns:
            report.warnings.append({"index": index, "name": record["name"], "message": w})
        report.records.append(record)
    return report


class _SkipMap(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _map_to_record(index: int, m: dict[str, Any], raw_map: dict[str, Any], data: bytes, fw: dict[str, Any],
                   source_name: str, source_sha: str, now: str) -> tuple[dict[str, Any], list[str]]:
    warns: list[str] = []
    ols_type = m.get("Type")
    if ols_type not in SHAPES:
        raise _SkipMap("UNSUPPORTED_TYPE", f"Type {ols_type!r} is not one of {sorted(SHAPES)}")
    org = m.get("DataOrg")
    if org not in DATA_ORG:
        raise _SkipMap("UNSUPPORTED_DATA_ORG", f"DataOrg {org!r} is not supported")
    for key in ("SkipBytes", "LineSkipBytes"):
        if _int(m.get(key, "0")) != 0:
            raise _SkipMap("UNSUPPORTED_SKIP_BYTES", f"{key}={m.get(key)} (non-contiguous storage) is not supported yet")
    try:
        start = parse_address(m.get("Fieldvalues.StartAddr", "0"))
    except ValueError:
        raise _SkipMap("BAD_ADDRESS", f"cannot parse address {m.get('Fieldvalues.StartAddr')!r}") from None
    if start is None:
        raise _SkipMap("MISSING_ADDRESS", "Fieldvalues.StartAddr is empty or 0")

    columns, rows = _int(m.get("Columns", "1")), _int(m.get("Rows", "1"))
    if columns < 1 or rows < 1:
        raise _SkipMap("ZERO_DIMENSION", f"Columns={columns} Rows={rows}")
    shape = SHAPES[ols_type]
    if shape == "scalar" and columns * rows != 1:
        warns.append(f"eEinzel with {rows}x{columns} cells; treated as a map")
        shape = "map"

    code, size, byte_order, is_float = DATA_ORG[org]
    signed = _int(m.get("bSigned", "0")) == 1 and not is_float
    end = start + rows * columns * size
    if end > len(data):
        raise _SkipMap("OFFSET_OUT_OF_RANGE", f"range 0x{start:X}-0x{end:X} is past the end of the BIN ({len(data)} bytes)")

    factor = parse_number(m.get("Fieldvalues.Factor", "1"))
    offset = parse_number(m.get("Fieldvalues.Offset", "0"))
    reciprocal = _int(m.get("bReciprocal", "0")) == 1
    formula = _formula(factor, offset, reciprocal)
    if reciprocal:
        warns.append("bReciprocal=1: formula stored as 1/(factor*X+offset); verify against WinOLS before approving")

    raw_bytes = data[start:end]
    raw = _decode(raw_bytes, code, size, byte_order, signed, rows * columns)
    physical = [_phys(v, factor, offset, reciprocal) for v in raw]
    axes = []
    for axis_key, kind, points in (("AxisX", "x", columns), ("AxisY", "y", rows)):
        if points <= 1:
            continue
        axis, axis_warns = _axis(m, axis_key, kind, points, data)
        axes.append(axis)
        warns += axis_warns

    id_name = str(m.get("IdName") or "")
    map_key = re.sub(r"[^A-Za-z0-9_.]", "_", id_name) or f"map_{start:X}"
    display_name = str(m.get("Name") or id_name or f"Map at 0x{start:X}")
    record_id = f"ols-{fw['sha256'][:12]}-{start:X}-{map_key}"[:128]

    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "record_id": record_id,
        "revision": 1,
        "category": "function_map_table",
        "name": display_name,
        "description": (str(m.get("Comment")) or None) if m.get("Comment") else None,
        "software_id": fw.get("software_id"),
        "calibration_id": fw.get("calibration_id"),
        "ecu_vendor": fw.get("ecu_vendor"),
        "ecu_family": fw.get("ecu_family") or "unknown",
        "processor": fw.get("processor"),
        "file_size": fw["file_size"],
        "md5": fw["md5"],
        "sha256": fw["sha256"],
        "file_offset": start,
        "ecu_address": None,
        "end_file_offset": end,
        "byte_order": byte_order,
        "original_bytes": to_hex(raw_bytes),
        "evidence": [
            {"source_type": "ols", "source_ref": f"{source_name}#maps[{index}]",
             "claim": f"OLS map-pack defines '{display_name}' at ${start:X} as {ols_type}/{org}",
             "file_offset": start, "verified_against_bin": False},
            {"source_type": "binary_check", "source_ref": fw["sha256"],
             "claim": f"{end - start} bytes read from the BIN at 0x{start:X}; range is inside the file",
             "file_offset": start, "verified_against_bin": True},
        ],
        "confidence": 0.6,
        "review_state": "draft",
        "reviewer": None,
        "created_at": now,
        "updated_at": now,
        "provenance": [{"source_type": FORMAT_NAME, "source_name": source_name, "sha256": source_sha,
                        "license": None, "imported_at": now}],
        "validation_steps": ["range inside BIN", "bytes read from BIN", "needs human review"],
        "map_key": map_key,
        "shape": shape,
        "data_type": _TYPE_NAMES[(code, signed)],
        "rows": rows,
        "columns": columns,
        "storage_order": "row_major",
        "formula": formula,
        "unit": _unit(m.get("Fieldvalues.Unit")),
        "axes": axes,
        "original_raw_bytes": to_hex(raw_bytes),
        "original_physical_values": [physical[r * columns:(r + 1) * columns] for r in range(rows)],
        "proposed_physical_values": None,
        "proposed_bytes": None,
        "related_functions": [],
        "x_ols_source": raw_map,
    }
    folder = m.get("FolderName")
    if folder:
        record["x_ols_folder"] = folder
    return record, warns


def _axis(m: dict[str, Any], key: str, kind: str, points: int, data: bytes) -> tuple[dict[str, Any], list[str]]:
    warns: list[str] = []
    src = m.get(f"{key}.DataSrc", "eUserdef")
    unit = _unit(m.get(f"{key}.Unit"))
    name = str(m.get(f"{key}.IdName") or m.get(f"{key}.Name") or f"{kind} axis")
    factor = parse_number(m.get(f"{key}.Factor", "1"))
    offset = parse_number(m.get(f"{key}.Offset", "0"))
    reciprocal = _int(m.get(f"{key}.bReciprocal", "0")) == 1
    axis: dict[str, Any] = {"name": name, "kind": kind, "points": points, "unit": unit,
                            "formula": _formula(factor, offset, reciprocal)}
    if src == "eRom":
        org = m.get(f"{key}.DataOrg", "eByte")
        addr = parse_address(m.get(f"{key}.DataAddr", "0"))
        if org not in DATA_ORG or addr is None:
            warns.append(f"{key}: stored axis without a usable address/DataOrg; values left empty")
            axis.update(source="stored", file_offset=addr, values=None)
            return axis, warns
        code, size, byte_order, is_float = DATA_ORG[org]
        signed = _int(m.get(f"{key}.bSigned", "0")) == 1 and not is_float
        end = addr + points * size
        axis.update(source="stored", file_offset=addr, ecu_address=None, data_type=_TYPE_NAMES[(code, signed)],
                    byte_order=byte_order)
        if end > len(data):
            warns.append(f"{key}: axis range 0x{addr:X}-0x{end:X} is past the end of the BIN; values left empty")
            axis["values"] = None
        else:
            raw = _decode(data[addr:end], code, size, byte_order, signed, points)
            axis["values"] = [_phys(v, factor, offset, reciprocal) for v in raw]
    else:
        text = str(m.get(f"{key}.Values", "")).strip()
        values = [float(v) for v in text.split()] if text else None
        if values is not None and len(values) != points:
            warns.append(f"{key}: {len(values)} fixed values for {points} points; values left empty")
            values = None
        axis.update(source="fixed", values=values)
    return axis, warns


def _decode(raw: bytes, code: str, size: int, byte_order: str, signed: bool, count: int) -> list[float]:
    fmt_code = code.lower() if signed and code in "BHI" else code
    prefix = ">" if byte_order == "big" else "<"
    return [float(v) for v in struct.unpack(f"{prefix}{count}{fmt_code}", raw[:count * size])]


def _formula(factor: float, offset: float, reciprocal: bool) -> dict[str, Any]:
    if reciprocal:
        # physical = (a*X + b) / (c + d*X) with a=0, b=1, c=offset, d=factor
        return {"type": "rational", "coefficients": [0.0, 1.0, offset, factor]}
    if factor == 1.0 and offset == 0.0:
        return {"type": "identity"}
    return {"type": "linear", "factor": factor, "offset": offset, "rounding": "none"}


def _phys(raw: float, factor: float, offset: float, reciprocal: bool) -> float:
    if reciprocal:
        denom = factor * raw + offset
        return round(1.0 / denom, 9) if denom else 0.0
    return round(raw * factor + offset, 9)


def _unit(text: Any) -> str | None:
    s = str(text or "").strip()
    return None if s in ("", "-", "--") else s


def _int(text: Any) -> int:
    try:
        return int(str(text).strip() or "0")
    except ValueError:
        return int(parse_number(text))


# ---- export -------------------------------------------------------------------------------------

def export_document(records: list[dict[str, Any]], decimal_comma: bool = True) -> dict[str, Any]:
    """Serialize function_map_table records to an OLS map-pack JSON document.

    Properties kept in x_ols_source (from an earlier import) are preserved; geometry, data layout,
    scaling and names always come from the record itself.
    """
    maps = []
    for r in records:
        if r.get("category") != "function_map_table":
            raise ValueError(f"record {r.get('record_id')} is not a function_map_table")
        maps.append(_record_to_map(r, decimal_comma))
    return {"maps": maps}


def _record_to_map(r: dict[str, Any], decimal_comma: bool) -> dict[str, Any]:
    out: dict[str, Any] = {k: v for k, v in (r.get("x_ols_source") or {}).items() if k not in DEFAULT_ALIASES}
    code, signed = _code_for(r["data_type"])
    byte_order = r["byte_order"] if code != "B" else "not_applicable"
    org = _DATA_ORG_BY_TYPE.get((code, byte_order)) or ("eByte" if code == "B" else None)
    if org is None:
        raise ValueError(f"cannot express data_type={r['data_type']} byte_order={r['byte_order']} as DataOrg")
    if r["shape"] == "scalar":
        ols_type = "eEinzel"
    elif r["shape"] == "curve":
        ols_type = "eZweiInv" if r["columns"] == 1 else "eEindim"
    else:
        ols_type = "eZweidim"
    factor, offset, reciprocal = _formula_parts(r["formula"])
    out.update({
        "Name": r["name"],
        "IdName": r["map_key"],
        "Type": ols_type,
        "DataOrg": org,
        "Columns": str(r["columns"]),
        "Rows": str(r["rows"]),
        "Fieldvalues.StartAddr": f"${r['file_offset']:X}",
        "Fieldvalues.Factor": format_number(factor, decimal_comma),
        "Fieldvalues.Offset": format_number(offset, decimal_comma),
        "Fieldvalues.Unit": r.get("unit") or out.get("Fieldvalues.Unit", "-"),
        "bSigned": "1" if signed else "0",
        "bReciprocal": "1" if reciprocal else "0",
    })
    out.setdefault("Comment", r.get("description") or "")
    out.setdefault("FolderName", r.get("x_ols_folder", ""))
    for axis in r.get("axes", []):
        key = "AxisX" if axis["kind"] == "x" else "AxisY"
        a_factor, a_offset, a_recip = _formula_parts(axis.get("formula") or {"type": "identity"})
        out[f"{key}.Factor"] = format_number(a_factor, decimal_comma)
        out[f"{key}.Offset"] = format_number(a_offset, decimal_comma)
        out[f"{key}.bReciprocal"] = "1" if a_recip else "0"
        out[f"{key}.Unit"] = axis.get("unit") or out.get(f"{key}.Unit", "-")
        if axis.get("source") == "stored" and axis.get("file_offset") is not None:
            a_code, a_signed = _code_for(axis.get("data_type", "uint8"))
            a_order = axis.get("byte_order", "not_applicable") if a_code != "B" else "not_applicable"
            out[f"{key}.DataSrc"] = "eRom"
            out[f"{key}.DataAddr"] = f"${axis['file_offset']:X}"
            out[f"{key}.DataOrg"] = _DATA_ORG_BY_TYPE.get((a_code, a_order), "eByte")
            out[f"{key}.bSigned"] = "1" if a_signed else "0"
        else:
            out[f"{key}.DataSrc"] = "eUserdef"
            out[f"{key}.DataAddr"] = "0"
            values = axis.get("values")
            out[f"{key}.Values"] = " ".join(f"{v:.1f}" if float(v).is_integer() else str(v) for v in values) if values else ""
    return out


def _code_for(data_type: str) -> tuple[str, bool]:
    for (code, signed), name in _TYPE_NAMES.items():
        if name == data_type and (code not in "fd" or not signed):
            return code, signed
    raise ValueError(f"unsupported data_type {data_type!r} for OLS export")


def _formula_parts(formula: dict[str, Any]) -> tuple[float, float, bool]:
    t = formula.get("type")
    if t == "identity":
        return 1.0, 0.0, False
    if t == "linear":
        return float(formula["factor"]), float(formula["offset"]), False
    if t == "rational":
        a, b, c, d = (list(formula["coefficients"]) + [0, 0, 0, 0])[:4]
        if a == 0 and b == 1:
            return float(d), float(c), True
    raise ValueError(f"formula type {t!r} cannot be expressed in OLS map-pack JSON")
