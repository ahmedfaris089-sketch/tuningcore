import json
from pathlib import Path

import pytest

from core.importers import ols_json
from core.validators import ContractValidator, check_against_bin
from tests.conftest import upload

ROOT = Path(__file__).resolve().parents[1]
OLS = ROOT / "fixtures" / "synthetic" / "synthetic_ols.json"
BIN = (ROOT / "fixtures" / "synthetic" / "synthetic_ecu.bin").read_bytes()
FW = {"sha256": "8" * 64, "md5": "0" * 32, "file_size": len(BIN), "software_id": "SYN0001",
      "calibration_id": "CAL0001", "ecu_vendor": "Synthetic", "ecu_family": "synthetic_test", "processor": None}


def doc():
    return json.loads(OLS.read_text())


def by_key(report):
    return {r["map_key"]: r for r in report.records}


@pytest.mark.parametrize("text,value", [("0,046882", 0.046882), ("0.5", 0.5), ("-273,128693", -273.128693), ("40", 40.0)])
def test_locale_numbers(text, value):
    assert ols_json.parse_number(text) == pytest.approx(value)


def test_addresses():
    assert ols_json.parse_address("$39C818") == 0x39C818
    assert ols_json.parse_address("0") is None
    assert ols_json.parse_address("0x10") == 16


def test_sniff():
    assert ols_json.looks_like_ols_json(doc())
    assert ols_json.looks_like_ols_json({"maps": []})
    assert not ols_json.looks_like_ols_json({"version": 1, "maps": [{"name": "x"}]})
    assert not ols_json.looks_like_ols_json([1, 2, 3])


def test_import_decodes_map_axes_and_scaling():
    report = ols_json.import_document(doc(), BIN, FW)
    torque = by_key(report)["syn_torque_limit"]
    assert (torque["shape"], torque["rows"], torque["columns"]) == ("map", 4, 4)
    assert (torque["data_type"], torque["byte_order"]) == ("uint16", "big")
    assert (torque["file_offset"], torque["end_file_offset"]) == (0x2000, 0x2020)
    assert torque["formula"] == {"type": "linear", "factor": 0.1, "offset": 0.0, "rounding": "none"}
    assert torque["original_physical_values"][0] == [100.0, 101.0, 102.0, 103.0]
    x, y = torque["axes"]
    assert x["values"] == [800, 1600, 2400, 3200] and x["unit"] == "rpm"
    assert y["values"] == [10, 20, 30, 40]


def test_import_scalar_and_vertical_curve():
    maps = by_key(ols_json.import_document(doc(), BIN, FW))
    fan = maps["syn_fan"]
    assert fan["shape"] == "scalar" and fan["original_bytes"] == "01" and fan["axes"] == []
    curve = maps["syn_curve"]
    assert (curve["shape"], curve["rows"], curve["columns"], curve["byte_order"]) == ("curve", 4, 1, "little")
    assert curve["axes"][0]["kind"] == "y" and curve["axes"][0]["values"] == [0.0, 1.0, 2.0, 3.0]


def test_nothing_dropped_silently():
    report = ols_json.import_document(doc(), BIN, FW)
    codes = {s.name: s.code for s in report.skipped}
    assert codes == {"Gapped map": "UNSUPPORTED_SKIP_BYTES", "Past the end": "OFFSET_OUT_OF_RANGE",
                     "No address": "MISSING_ADDRESS"}
    assert len(report.records) + len(report.skipped) == report.total_maps == 6


def test_duplicate_range_warns():
    d = doc()
    d["maps"].append({**d["maps"][0], "Name": "Torque copy", "IdName": "syn_torque_copy"})
    report = ols_json.import_document(d, BIN, FW)
    assert any(w["name"] == "Torque copy" and "same range" in w["message"] for w in report.warnings)


def test_aliases_map_german_keys():
    d = {"maps": [{"Name": "Alias", "Typ": "eEinzel", "DataOrg": "eByte", "Spalten": "1", "Zeilen": "1",
                   "Adresse": "$1000", "Faktor": "1,0"}]}
    report = ols_json.import_document(d, BIN, FW)
    assert report.records[0]["file_offset"] == 0x1000 and not report.skipped


def test_imported_records_pass_contract_and_bin_checks():
    v = ContractValidator(ROOT / "schemas")
    fw = {**FW, **_hashes()}
    for rec in ols_json.import_document(doc(), BIN, fw).records:
        issues = v.validate(rec) + check_against_bin(rec, BIN)
        assert [i for i in issues if i.severity == "error"] == [], rec["name"]


def test_export_round_trip_preserves_meaning():
    report = ols_json.import_document(doc(), BIN, FW)
    exported = ols_json.export_document(report.records, decimal_comma=True)
    assert exported["maps"][0]["Fieldvalues.StartAddr"] == "$2000"
    assert exported["maps"][0]["Fieldvalues.Factor"] == "0,100000"
    again = ols_json.import_document(exported, BIN, FW)
    strip = lambda r: {k: v for k, v in r.items() if k not in ("x_ols_source", "created_at", "updated_at", "provenance", "evidence")}
    assert [strip(r) for r in again.records] == [strip(r) for r in report.records]
    dot = ols_json.export_document(report.records, decimal_comma=False)
    assert dot["maps"][0]["Fieldvalues.Factor"] == "0.100000"


def test_rejects_non_ols_document():
    with pytest.raises(ols_json.OlsFormatError):
        ols_json.import_document({"version": 1}, BIN, FW)


def _hashes():
    import hashlib
    return {"sha256": hashlib.sha256(BIN).hexdigest(), "md5": hashlib.md5(BIN).hexdigest()}


# ---- API ----------------------------------------------------------------------------------------

def post_ols(client, firmware_id, apply, content=None):
    return client.post("/api/v1/sources/import/ols-json",
                       files={"file": ("synthetic_ols.json", content or OLS.read_bytes(), "application/json")},
                       data={"firmware_id": str(firmware_id), "apply": str(apply).lower()})


def test_api_preview_then_apply_then_idempotent(client, synthetic_bin):
    fw = upload(client, synthetic_bin, software_id="SYN0001", calibration_id="CAL0001", ecu_family="synthetic_test").json()
    preview = post_ols(client, fw["id"], False).json()
    assert (preview["would_create"], preview["skipped"], preview["created"]) == (3, 3, 0)
    assert client.get("/api/v1/definitions").json() == []

    applied = post_ols(client, fw["id"], True).json()
    assert applied["created"] == 3 and applied["rejected"] == 0
    defs = client.get("/api/v1/definitions", params={"category": "function_map_table"}).json()
    assert len(defs) == 3

    again = post_ols(client, fw["id"], True).json()
    assert (again["created"], again["unchanged"], again["rejected"]) == (0, 3, 0)


def test_reimport_after_clock_moves_is_unchanged(client, synthetic_bin, monkeypatch):
    """Regression: a re-import one second later used to be rejected as REVISION_CONFLICT."""
    import datetime as dt
    fw = upload(client, synthetic_bin).json()
    post_ols(client, fw["id"], True)

    class Later(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime(2030, 1, 1, tzinfo=tz)

    monkeypatch.setattr(ols_json, "datetime", Later)
    again = post_ols(client, fw["id"], True).json()
    assert (again["unchanged"], again["rejected"]) == (3, 0)


def test_api_export_ols(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    post_ols(client, fw["id"], True)
    ids = [d["record_id"] for d in client.get("/api/v1/definitions").json()]
    out = client.post("/api/v1/exports/ols-json", json={"record_ids": ids}).json()
    assert len(out["maps"]) == 3 and all(m["Fieldvalues.StartAddr"].startswith("$") for m in out["maps"])


def test_api_bad_json(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    r = post_ols(client, fw["id"], False, content=b"{not json")
    assert r.status_code == 422 and r.json()["error"]["code"] == "INVALID_JSON"
    r = post_ols(client, fw["id"], False, content=b'{"version": 1}')
    assert r.json()["error"]["code"] == "UNSUPPORTED_SOURCE_FORMAT"
