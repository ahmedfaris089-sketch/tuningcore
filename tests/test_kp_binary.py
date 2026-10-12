import csv
import io
import math
import os
import struct
import zipfile
from pathlib import Path

import pytest

from core.importers.kp_binary import KpParseError, parse_kp, to_ols_document
from tests.conftest import upload

MAP_AT, X_AT, Y_AT = 0x5000, 0x5100, 0x5110


def _text(buf: bytearray, offset: int, value: str) -> int:
    encoded = value.encode("cp1252") + b"\x00"
    buf[offset:offset + len(encoded)] = encoded
    return offset + len(encoded)


def kp_file(*, factor=0.5, signed=True, address=MAP_AT, x_size=1, y_size=2) -> bytes:
    """One 3x2 16-bit map with a stored X axis (x_size bytes/point) and Y axis (y_size bytes/point)."""
    record = bytearray(512)
    _text(record, 16, "Synthetic torque limiter")
    name_end = _text(record, 64, "KFSYNTH (AR 005000)")
    record[name_end + 58] = 1 if signed else 0
    struct.pack_into("<II", record, name_end + 61, 3, 2)
    z = _text(record, name_end + 89, "Nm")
    struct.pack_into("<d", record, z, factor)
    struct.pack_into("<II", record, z + 16, address, address + 3 * 2 * 2)
    x = _text(record, z + 64, "rpm")
    struct.pack_into("<d", record, x, 40.0)
    struct.pack_into("<I", record, x + 20, X_AT)
    struct.pack_into("<I", record, x + 28, x_size)
    y = _text(record, x + 75, "%")
    struct.pack_into("<d", record, y, 0.75)
    struct.pack_into("<I", record, y + 20, Y_AT)
    struct.pack_into("<I", record, y + 28, y_size)
    struct.pack_into("<I", record, 0, len(record))

    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("intern", bytes(record))
    head = bytearray(64)
    head[:16] = b"\x0b\x00\x00\x00WinOLS File\x00"
    struct.pack_into("<I", head, 0x10, 292)
    out = head + zipped.getvalue()
    struct.pack_into("<I", out, 0x14, len(out))
    return bytes(out)


def test_parse_reads_sizes_sign_and_axes():
    result = parse_kp(kp_file(), rom_size=0x10000)
    assert result.format_version == 292 and result.rejected == []
    m = result.maps[0]
    assert (m.name, m.description, m.columns, m.rows) == ("KFSYNTH", "Synthetic torque limiter", 3, 2)
    assert (m.file_offset, m.element_bytes, m.signed, m.factor, m.unit) == (MAP_AT, 2, True, 0.5, "Nm")
    x, y = m.axes
    assert (x.name, x.file_offset, x.element_bytes, x.factor, x.unit) == ("X", X_AT, 1, 40.0, "rpm")
    assert (y.name, y.file_offset, y.element_bytes, y.factor, y.unit) == ("Y", Y_AT, 2, 0.75, "%")


def test_implausible_factor_is_reported_not_kept():
    result = parse_kp(kp_file(factor=0.0), rom_size=0x10000)
    assert result.maps == []
    assert [(r.name, r.code) for r in result.rejected] == [("KFSYNTH", "IMPLAUSIBLE_SCALING")]


def test_address_outside_bin_is_reported():
    result = parse_kp(kp_file(address=0x80005000), rom_size=0x10000)
    assert [r.code for r in result.rejected] == ["ADDRESS_OUTSIDE_BIN"]
    mapped = parse_kp(kp_file(address=0x80005000), rom_size=0x10000, base_address=0x80000000)
    assert mapped.maps[0].file_offset == MAP_AT


def test_unreadable_axis_size_falls_back_with_a_note():
    result = parse_kp(kp_file(x_size=7), rom_size=0x10000)
    assert result.maps[0].axes[0].element_bytes is None
    doc, source, notes = to_ols_document(result, "maps.kp")
    assert doc["maps"][0]["AxisX.DataOrg"] == "eLoHi"
    assert notes[0] == ["X axis element size not readable; map size (2 bytes) assumed"]
    assert source.evidence_type == "kp" and source.refs[0].startswith("maps.kp#intern+")


def test_rejects_non_kp():
    with pytest.raises(KpParseError):
        parse_kp(b"not a KP file")


def test_api_import_kp_creates_drafts_from_bin_bytes(client, synthetic_bin):
    fw = upload(client, synthetic_bin, software_id="SYN0001", calibration_id="CAL0001").json()
    files = {"file": ("maps.kp", kp_file())}
    preview = client.post("/api/v1/sources/import/kp", files=files, data={"firmware_id": fw["id"]}).json()
    assert preview["format"] == "winols_kp" and preview["would_create"] == 1 and preview["applied"] is False
    assert preview["decoded_maps"] == 1 and preview["rejected"] == [] and preview["assumptions"]

    done = client.post("/api/v1/sources/import/kp", files=files,
                       data={"firmware_id": fw["id"], "apply": "true"}).json()
    assert done["created"] == 1
    record_id = done["items"][0]["record_id"]
    rec = client.get(f"/api/v1/definitions/{record_id}").json()["revisions"][-1]["payload"]
    assert rec["review_state"] == "draft" and rec["data_type"] == "int16" and (rec["rows"], rec["columns"]) == (2, 3)
    assert rec["original_bytes"] == " ".join(f"{b:02X}" for b in synthetic_bin[MAP_AT:MAP_AT + 12])
    assert [a.get("data_type") for a in rec["axes"]] == ["uint8", "uint16"]
    assert rec["axes"][0]["values"] == [40.0 * b for b in synthetic_bin[X_AT:X_AT + 3]]
    assert rec["evidence"][0]["source_type"] == "kp" and rec["provenance"][0]["source_type"] == "winols_kp"

    again = client.post("/api/v1/sources/import/kp", files=files,
                        data={"firmware_id": fw["id"], "apply": "true"}).json()
    assert again["unchanged"] == 1 and again["created"] == 0


def test_api_rejects_bad_input(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    r = client.post("/api/v1/sources/import/kp", files={"file": ("x.kp", b"nope")}, data={"firmware_id": fw["id"]})
    assert r.status_code == 422 and r.json()["error"]["code"] == "UNSUPPORTED_SOURCE_FORMAT"
    r = client.post("/api/v1/sources/import/kp", files={"file": ("x.kp", kp_file())},
                    data={"firmware_id": fw["id"], "base_address": "zz"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "INVALID_BASE_ADDRESS"


# Opt-in check against a real map pack: set AKTOOL_REAL_KP to a .kp and AKTOOL_REAL_KP_CSV to the WinOLS CSV
# export of the same maps (e.g. MxT's example/me7/kp/8D0907551M-20190711.*). Real files stay out of this repo.
REAL_KP, REAL_CSV = os.environ.get("AKTOOL_REAL_KP"), os.environ.get("AKTOOL_REAL_KP_CSV")


@pytest.mark.skipif(not (REAL_KP and REAL_CSV), reason="no real KP sample configured")
def test_real_kp_matches_winols_csv():
    rom_size = int(os.environ.get("AKTOOL_REAL_KP_ROM_SIZE", "0x100000"), 0)
    result = parse_kp(Path(REAL_KP).read_bytes(), rom_size=rom_size)
    truth = {}
    for row in csv.DictReader(open(REAL_CSV, encoding="cp1252", errors="replace")):
        truth.setdefault(int(row["Address"], 16), row)
    wrong = []
    for m in result.maps:
        row = truth.get(m.ecu_address)
        if row is None:
            wrong.append((m.name, "no CSV row at this address"))
            continue
        cols, rows = (int(v) for v in row["Size"].split("x"))
        size = {"8": 1, "16": 2, "32": 4}[row["Organization"].split()[0]]
        if (cols, rows, size) != (m.columns, m.rows, m.element_bytes) or not math.isclose(
                float(row["Scale"]), m.factor, rel_tol=1e-3):
            wrong.append((m.name, row["Size"], row["Organization"], row["Scale"]))
    assert result.maps and wrong == []
