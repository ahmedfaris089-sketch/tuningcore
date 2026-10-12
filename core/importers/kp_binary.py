# SPDX-License-Identifier: Apache-2.0
# KP record layout adapted from TracqiTechnology/MxT (KpHintParser.kt, Apache License 2.0) by way of the
# AKTOOL local backend's kp.py. Changes here: axis element size and the signed flag are read from the
# record, implausible decodes are reported instead of kept, and maps are handed to the OLS importer.
"""WinOLS .kp (map pack) reader. Read-only; the KP file is never modified.

A .kp file is a WinOLS header followed by a ZIP archive whose "intern" entry holds length-prefixed
records. A map record contains "<NAME> (AR <hex>)", then at fixed distances from the end of that string:

* name_end + 58: 1 when the map values are signed
* name_end + 61 / + 65: u32 columns / rows
* name_end + 89: unit string, then f64 factor, u32 start address (+16), u32 end address (+20)
* each axis: unit string, then f64 factor, u32 address (+20), u32 element size in bytes (+28)

Checked against a real ME7 KP (8D0907551M) and its WinOLS CSV export and XDF: 94 of 95 maps match
address, size, data width and factor; the remaining one is a misdecode that the factor check rejects.

Not decoded yet: byte order (little endian is assumed), the map's additive offset (0 is assumed) and
the axes' sign (unsigned is assumed). Every resulting record is a draft that needs review.
"""

from __future__ import annotations

import hashlib
import io
import math
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Any

from core.importers.ols_json import SourceInfo

FORMAT_NAME = "winols_kp"
PARSER_PROFILE = "winols-kp-record-v2"
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_INTERN_SIZE = 64 * 1024 * 1024
MAX_RECORD_SIZE = 200_000
ZIP_MAGIC = b"PK\x03\x04"
OLS_SIGNATURE = b"\x0b\x00\x00\x00WinOLS File\x00"
NAME_ADDRESS_RE = re.compile(rb"([A-Z][A-Z0-9_]{1,31}) \(AR ([0-9A-Fa-f]{4,8})")
FACTOR_RANGE = (1e-12, 1e12)
ASSUMPTIONS = ("byte order is not stored where this parser reads; little endian is assumed",
               "the map offset is not decoded; 0 is assumed",
               "axis sign is not decoded; unsigned is assumed")


class KpParseError(ValueError):
    """Invalid, unsafe, or unsupported KP input."""


@dataclass
class KpAxis:
    name: str
    points: int
    unit: str | None
    ecu_address: int | None
    file_offset: int | None
    factor: float
    element_bytes: int | None  # None when the size field was not readable


@dataclass
class KpMap:
    record_offset: int
    name: str
    description: str
    ecu_address: int
    file_offset: int | None
    columns: int
    rows: int
    element_bytes: int
    signed: bool
    factor: float
    unit: str | None
    axes: list[KpAxis] = field(default_factory=list)


@dataclass
class KpRejected:
    record_offset: int
    name: str
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"record_offset": self.record_offset, "name": self.name, "code": self.code, "message": self.message}


@dataclass
class KpParseResult:
    sha256: str
    file_size: int
    format_version: int | None
    maps: list[KpMap]
    rejected: list[KpRejected]
    warnings: list[str]

    def info(self) -> dict[str, Any]:
        return {"parser_profile": PARSER_PROFILE, "kp_sha256": self.sha256, "kp_size": self.file_size,
                "format_version": self.format_version, "decoded_maps": len(self.maps),
                "rejected": [r.to_dict() for r in self.rejected], "kp_warnings": self.warnings,
                "assumptions": list(ASSUMPTIONS)}


def parse_kp(data: bytes, *, rom_size: int | None = None, base_address: int | None = None) -> KpParseResult:
    if not data:
        raise KpParseError("KP file is empty")
    if len(data) > MAX_FILE_SIZE:
        raise KpParseError("KP file exceeds the safe size limit")
    if base_address is not None and base_address < 0:
        raise KpParseError("base_address must not be negative")
    warnings: list[str] = []
    version = None
    if data.startswith(OLS_SIGNATURE) and len(data) >= 24:
        version = _u32(data, 0x10)
        declared = _u32(data, 0x14)
        if declared not in (0, len(data)):
            warnings.append(f"header declares {declared} bytes, file has {len(data)}")
    else:
        warnings.append("WinOLS header not recognised")
    intern = _extract_intern(data)
    maps, rejected, decode_warnings = _decode_intern(intern, rom_size, base_address)
    return KpParseResult(hashlib.sha256(data).hexdigest(), len(data), version, maps, rejected,
                         warnings + decode_warnings)


def to_ols_document(result: KpParseResult, source_name: str) -> tuple[dict[str, Any], SourceInfo, list[str]]:
    """Express decoded maps as an OLS map-pack document so the OLS importer builds the records.

    Returns the document, the SourceInfo that marks the records as coming from this KP, and per-map
    warnings (index-aligned with the document's maps) about what the KP did not provide.
    """
    maps, refs, notes = [], [], []
    for m in result.maps:
        cells = m.columns * m.rows
        ols_type = "eEinzel" if cells == 1 else "eZweidim" if m.columns > 1 and m.rows > 1 else \
            "eEindim" if m.columns > 1 else "eZweiInv"
        entry: dict[str, Any] = {
            "Name": m.description or m.name, "IdName": m.name, "Type": ols_type,
            "Columns": str(m.columns), "Rows": str(m.rows), "DataOrg": _data_org(m.element_bytes),
            "bSigned": "1" if m.signed else "0",
            "Fieldvalues.StartAddr": f"${m.file_offset:X}" if m.file_offset is not None else "0",
            "Fieldvalues.Factor": repr(m.factor), "Fieldvalues.Offset": "0", "Fieldvalues.Unit": m.unit or "",
        }
        note = []
        for axis, key, points in (("X", "AxisX", m.columns), ("Y", "AxisY", m.rows)):
            if points <= 1:
                continue
            a = next((a for a in m.axes if a.name == axis), None)
            if a is None or a.file_offset is None:
                note.append(f"{axis} axis was not decoded from the KP")
                continue
            size = a.element_bytes or m.element_bytes
            if a.element_bytes is None:
                note.append(f"{axis} axis element size not readable; map size ({size} bytes) assumed")
            entry.update({f"{key}.DataSrc": "eRom", f"{key}.DataAddr": f"${a.file_offset:X}",
                          f"{key}.DataOrg": _data_org(size), f"{key}.Factor": repr(a.factor),
                          f"{key}.Offset": "0", f"{key}.Unit": a.unit or "", f"{key}.Name": f"{axis} axis"})
        maps.append(entry)
        refs.append(f"{source_name}#intern+{m.record_offset}")
        notes.append(note)
    source = SourceInfo(format=FORMAT_NAME, evidence_type="kp", label="KP record", id_prefix="kp",
                        sha256=result.sha256, refs=refs)
    return {"maps": maps}, source, notes


# ---- decoding -------------------------------------------------------------------------------------
def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, offset)[0]


def _f64(data: bytes, offset: int) -> float:
    if offset < 0 or offset + 8 > len(data):
        return math.nan
    return struct.unpack_from("<d", data, offset)[0]


def _cstring(data: bytes, offset: int, limit: int = 8192) -> tuple[str, int] | None:
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset, min(len(data), offset + limit + 1))
    if end < 0:
        return None
    text = data[offset:end].decode("cp1252", errors="replace")
    return "".join(ch for ch in text if ch.isprintable()).strip(), end + 1


def _plausible_factor(value: float) -> bool:
    return math.isfinite(value) and FACTOR_RANGE[0] <= abs(value) <= FACTOR_RANGE[1]


def _data_org(size: int) -> str:
    return {1: "eByte", 2: "eLoHi", 4: "eLoHiLoHi"}[size]


def _file_offset(address: int | None, rom_size: int | None, base_address: int | None, length: int) -> int | None:
    if address is None or address < 0:
        return None
    if rom_size is None:
        return address - base_address if base_address is not None and address >= base_address else address
    if address + length <= rom_size:
        return address
    if base_address is not None and base_address <= address and address + length <= base_address + rom_size:
        return address - base_address
    return None


def _axis_field(data: bytes, preferred: int, scan_start: int, scan_stop: int) -> tuple[str, int] | None:
    for offset in [preferred, *range(max(0, scan_start), min(scan_stop, len(data) - 1))]:
        value = _cstring(data, offset, 20)
        if value is None:
            continue
        text, end = value
        allowed = set(" %/°._-*^³²µ()")
        if not 1 <= len(text) <= 20 or "�" in text or not all(c.isalnum() or c in allowed for c in text):
            continue
        if _plausible_factor(_f64(data, end)):
            return text, end
    return None


def _extract_intern(data: bytes) -> bytes:
    zip_offset = data.find(ZIP_MAGIC)
    if zip_offset < 0:
        raise KpParseError("embedded KP ZIP archive was not found")
    try:
        with zipfile.ZipFile(io.BytesIO(data[zip_offset:])) as archive:
            entries = archive.infolist()
            if len(entries) > 32:
                raise KpParseError("KP archive contains too many entries")
            intern_info = None
            for info in entries:
                name = info.filename.replace("\\", "/").strip("/")
                if info.file_size > MAX_INTERN_SIZE:
                    raise KpParseError("KP intern entry exceeds the safe limit")
                if info.compress_size and info.file_size / info.compress_size > 250:
                    raise KpParseError("KP archive compression ratio is unsafe")
                if name == "intern":
                    intern_info = info
            if intern_info is None:
                raise KpParseError("KP archive does not contain an intern entry")
            intern = archive.read(intern_info)
    except KpParseError:
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
        raise KpParseError(f"invalid KP archive: {exc}") from exc
    if not intern:
        raise KpParseError("KP intern entry is empty")
    return intern


def _decode_axis(record: bytes, name: str, points: int, field_at: tuple[str, int], rom_size: int | None,
                 base_address: int | None, fallback_bytes: int) -> KpAxis:
    unit, values = field_at
    size = _u32(record, values + 28)
    element_bytes = size if size in (1, 2, 4) else None
    address = _u32(record, values + 20) or None
    length = points * (element_bytes or fallback_bytes)
    return KpAxis(name, points, unit or None, address, _file_offset(address, rom_size, base_address, length),
                  _f64(record, values), element_bytes)


def _decode_map(record: bytes, record_offset: int, name: str, description: str, name_end: int,
                rom_size: int | None, base_address: int | None) -> KpMap | KpRejected:
    def reject(code: str, message: str) -> KpRejected:
        return KpRejected(record_offset, name, code, message)

    if name_end + 89 >= len(record):
        return reject("TRUNCATED_RECORD", "record ends before the map fields")
    columns, rows = _u32(record, name_end + 61), _u32(record, name_end + 65)
    if not (1 <= columns <= 1000 and 1 <= rows <= 1000):
        return reject("BAD_DIMENSIONS", f"columns={columns} rows={rows}")
    unit_field = _cstring(record, name_end + 89, 64)
    if unit_field is None:
        return reject("TRUNCATED_RECORD", "unit string is not terminated")
    unit, values = unit_field
    factor = _f64(record, values)
    if not _plausible_factor(factor):
        return reject("IMPLAUSIBLE_SCALING", f"factor {factor!r} is outside {FACTOR_RANGE}")
    address, end_address = _u32(record, values + 16), _u32(record, values + 20)
    if address <= 0:
        return reject("MISSING_ADDRESS", "map address is 0")
    cells = columns * rows
    span = end_address - address if end_address > address else 0
    element_bytes = span // cells if span and span % cells == 0 else 0
    if element_bytes not in (1, 2, 4):
        return reject("UNKNOWN_DATA_SIZE", f"address range {span} bytes does not fit {cells} cells of 1, 2 or 4 bytes")
    flag = record[name_end + 58]
    if flag not in (0, 1):
        return reject("UNKNOWN_SIGN_FLAG", f"sign flag byte is {flag}")
    offset = _file_offset(address, rom_size, base_address, cells * element_bytes)
    if offset is None:
        return reject("ADDRESS_OUTSIDE_BIN", f"address 0x{address:X} ({cells * element_bytes} bytes) is not inside "
                                             "the firmware; pass base_address if the KP uses ECU addresses")
    item = KpMap(record_offset, name, description, address, offset, columns, rows, element_bytes, flag == 1,
                 factor, unit or None)

    x_values = None
    if columns > 1:
        x = _axis_field(record, values + 64, values + 48, values + 80)
        if x is not None:
            x_values = x[1]
            item.axes.append(_decode_axis(record, "X", columns, x, rom_size, base_address, element_bytes))
    if rows > 1:
        where = (values + 64, values + 48, values + 80) if x_values is None else \
            (x_values + 75, x_values + 60, x_values + 100)
        y = _axis_field(record, *where)
        if y is not None:
            item.axes.append(_decode_axis(record, "Y", rows, y, rom_size, base_address, element_bytes))
    return item


def _decode_intern(intern: bytes, rom_size: int | None,
                   base_address: int | None) -> tuple[list[KpMap], list[KpRejected], list[str]]:
    maps: list[KpMap] = []
    rejected: list[KpRejected] = []
    seen: set[tuple[str, int]] = set()
    skipped = 0
    position = 0
    while position <= len(intern) - 8:
        size = _u32(intern, position)
        if not 50 <= size <= MAX_RECORD_SIZE or position + size > len(intern):
            position += 1
            skipped += 1
            continue
        record = intern[position:position + size]
        description_field = _cstring(record, 16)
        description = description_field[0] if description_field else ""
        for match in NAME_ADDRESS_RE.finditer(record, 16):
            terminator = record.find(b"\x00", match.end())
            if terminator < 0:
                continue
            name = match.group(1).decode("ascii")
            item = _decode_map(record, position + match.start(), name, description, terminator + 1, rom_size,
                               base_address)
            if isinstance(item, KpRejected):
                rejected.append(item)
            elif (item.name, item.ecu_address) not in seen:
                seen.add((item.name, item.ecu_address))
                maps.append(item)
        position += size
    decoded = {m.name for m in maps}
    rejected = [r for r in rejected if r.name not in decoded]  # another occurrence of the name decoded fine
    warnings = []
    if skipped:
        warnings.append(f"skipped {skipped} byte(s) that do not start a record")
    if not maps and not rejected:
        warnings.append("no KP map records were recognised")
    maps.sort(key=lambda m: (m.name, m.ecu_address))
    return maps, rejected, warnings
