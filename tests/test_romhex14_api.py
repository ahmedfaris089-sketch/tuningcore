import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.api import create_app
from core.checksum import ChecksumRegistry
from core.settings import Settings
from tests.conftest import upload

VALID = Path(__file__).resolve().parents[1] / "schemas" / "examples" / "valid"
FAMILY = "synthetic_test"


def example(category: str, **changes) -> dict:
    rec = json.loads((VALID / f"{category}.json").read_text())
    rec.update(changes)
    return rec


def stamp_last_byte(data: bytes) -> bytes:
    """Stand-in checksum: last byte = sum of all other bytes mod 256."""
    return data[:-1] + bytes([sum(data[:-1]) % 256])


def make_client(tmp_path, *, mode="local", api_key=None, policy="require", corrector=None):
    checksums = ChecksumRegistry()
    if corrector is not None:
        checksums.register(FAMILY, corrector)
    settings = Settings(mode=mode, data_dir=tmp_path / "data", api_key=api_key, rx14_checksum=policy)
    return TestClient(create_app(settings, checksums=checksums))


def seed(c, synthetic_bin, headers=None):
    """Approved records for the synthetic BIN, each carrying a reviewed change."""
    c.post("/api/v1/firmware", files={"file": ("stock.bin", synthetic_bin)}, headers=headers or {},
           data={"software_id": "SYN0001", "calibration_id": "CAL0001"})
    records = [
        example("bosch_dtc", proposed_strategy="clear mask word", proposed_bytes="00 00"),
        example("non_bosch_dtc", disable_strategy="clear enable pair", proposed_bytes="04 20 00 00"),
        example("function_on_off", proposed_state="off"),
    ]
    for rec in records:
        r = c.post("/api/v1/definitions", json={"record": rec}, headers=headers or {})
        assert r.status_code == 201, r.json()


def rom(data: bytes) -> dict:
    return {"rom": ("rom.bin", data, "application/octet-stream")}


@pytest.fixture
def rx(tmp_path, synthetic_bin):
    with make_client(tmp_path, corrector=stamp_last_byte) as c:
        seed(c, synthetic_bin)
        yield c


def test_health_shape(rx):
    body = rx.get("/v1/health").json()
    assert body["ok"] is True and body["engine"] == "ready" and body["service"] == "aktool"
    assert body["checksum_families"] == [FAMILY]


def test_analyze_lists_only_approved_dtcs_for_exact_file(rx, synthetic_bin):
    draft = example("bosch_dtc", record_id="syn-bosch_dtc-draft", dtc_code="P0999", review_state="draft",
                    reviewer=None)
    assert rx.post("/api/v1/definitions", json={"record": draft}).status_code == 201

    body = rx.post("/v1/dtc/analyze", files=rom(synthetic_bin), data={"family": "edc17"}).json()
    assert body["ok"] is True
    assert body["fid"] == hashlib.sha256(synthetic_bin).hexdigest()
    assert body["ecu"]["match"] == "exact"
    assert sorted(d["obd"] for d in body["dtcs"]) == ["P0123", "P0420"]
    assert body["dtcs_total"] == 2 and body["dtcs_on"] == 2 and body["dtcs_off"] == 0
    assert all(d["can_disable"] for d in body["dtcs"])


def test_analyze_unknown_file_returns_nothing_and_keeps_it(rx):
    other = os.urandom(4096)
    body = rx.post("/v1/dtc/analyze", files=rom(other)).json()
    assert body["ok"] is True and body["ecu"]["match"] == "unknown" and body["dtcs"] == []
    stored = rx.get("/api/v1/firmware", params={"q": hashlib.sha256(other).hexdigest()}).json()
    assert len(stored) == 1


def test_disable_patches_only_record_bytes_and_links_files(rx, synthetic_bin):
    r = rx.post("/v1/dtc/disable", files=rom(synthetic_bin), data={"codes": "P0420,P0123"})
    assert r.status_code == 200, r.json()
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["x-cloudfx-checksum"] == "corrected"
    assert r.headers["x-cloudfx-records"] == "syn-bosch_dtc-0001,syn-non_bosch_dtc-0001"
    out = r.content

    expected = bytearray(synthetic_bin)
    expected[16384:16388] = bytes.fromhex("04200000")
    expected[12298:12300] = bytes.fromhex("0000")
    assert out == stamp_last_byte(bytes(expected))

    fw = rx.get(f"/api/v1/firmware/{r.headers['x-cloudfx-firmware-id']}").json()
    assert fw["file_role"] == "modified" and fw["sha256"] == hashlib.sha256(out).hexdigest()
    assert [rel["relation_type"] for rel in fw["relations"]] == ["modified_from"]
    # The original stays untouched in the vault.
    original = rx.get("/api/v1/firmware", params={"q": hashlib.sha256(synthetic_bin).hexdigest()}).json()
    assert original[0]["file_role"] != "modified"


def test_disable_refuses_unknown_code(rx, synthetic_bin):
    r = rx.post("/v1/dtc/disable", files=rom(synthetic_bin), data={"codes": "P0123,P1234"})
    assert r.status_code == 422
    assert r.json() == {"ok": False, "error": "P1234: no approved record for this exact file",
                        "code": "DTC_NOT_KNOWN", "detail": {"code": "P1234"}}


def test_disable_on_other_file_finds_nothing(rx, synthetic_bin):
    changed = bytearray(synthetic_bin)
    changed[0] ^= 0xFF
    r = rx.post("/v1/dtc/disable", files=rom(bytes(changed)), data={"codes": "P0420"})
    assert r.status_code == 422 and r.json()["code"] == "DTC_NOT_KNOWN"


def test_no_checksum_corrector_means_no_file(tmp_path, synthetic_bin):
    with make_client(tmp_path) as c:
        seed(c, synthetic_bin)
        r = c.post("/v1/dtc/disable", files=rom(synthetic_bin), data={"codes": "P0420"})
    assert r.status_code == 422
    assert r.json()["code"] == "CHECKSUM_UNAVAILABLE" and r.json()["ok"] is False


def test_client_checksum_policy_returns_uncorrected_file(tmp_path, synthetic_bin):
    with make_client(tmp_path, policy="client") as c:
        seed(c, synthetic_bin)
        r = c.post("/v1/dtc/disable", files=rom(synthetic_bin), data={"codes": "P0420"})
    assert r.status_code == 200 and r.headers["x-cloudfx-checksum"] == "not_corrected"
    expected = bytearray(synthetic_bin)
    expected[16384:16388] = bytes.fromhex("04200000")
    assert r.content == bytes(expected)


def test_features_detect_and_apply(rx, synthetic_bin):
    body = rx.post("/v1/features/detect", files=rom(synthetic_bin)).json()
    assert body["ok"] is True
    assert body["available"]["synthetic_fan"]["state"] == "off"
    assert body["available"]["synthetic_fan"]["has_patches"] is True

    r = rx.post("/v1/features/apply", files=rom(synthetic_bin), data={"features": "synthetic_fan"})
    assert r.status_code == 200, r.json()
    expected = bytearray(synthetic_bin)
    expected[4096] = 0x00
    assert r.content == stamp_last_byte(bytes(expected))


def test_feature_without_proposed_state_is_not_offered(tmp_path, synthetic_bin):
    with make_client(tmp_path, corrector=stamp_last_byte) as c:
        upload(c, synthetic_bin)
        c.post("/api/v1/definitions", json={"record": example("function_on_off")})
        body = c.post("/v1/features/detect", files=rom(synthetic_bin)).json()
        assert body["available"] == {} and "synthetic_fan" in body["unavailable"]
        r = c.post("/v1/features/apply", files=rom(synthetic_bin), data={"features": "synthetic_fan"})
        assert r.status_code == 422 and r.json()["code"] == "NO_PROPOSED_STATE"


def test_newer_draft_revision_withdraws_record(rx, synthetic_bin):
    rec = example("non_bosch_dtc", disable_strategy="clear enable pair", proposed_bytes="04 20 00 00",
                  revision=2, review_state="draft", reviewer=None)
    assert rx.post(f"/api/v1/definitions/{rec['record_id']}/revisions", json={"record": rec}).status_code == 201
    body = rx.post("/v1/dtc/analyze", files=rom(synthetic_bin)).json()
    assert [d["obd"] for d in body["dtcs"]] == ["P0123"]


def test_missing_fields(rx, synthetic_bin):
    r = rx.post("/v1/dtc/analyze", data={"family": "x"})
    assert r.status_code == 400 and r.json()["error"] == "missing 'rom' field"
    r = rx.post("/v1/dtc/disable", files=rom(synthetic_bin))
    assert r.status_code == 400 and r.json()["error"] == "missing 'codes' field"
    assert rx.post("/v1/module/apply").status_code == 501


def test_server_mode_key_in_url_or_bearer(tmp_path, synthetic_bin):
    key = "s3cret"
    with make_client(tmp_path, mode="server", api_key=key, corrector=stamp_last_byte) as c:
        seed(c, synthetic_bin, headers={"X-API-Key": key})
        r = c.post("/v1/dtc/analyze", files=rom(synthetic_bin))
        assert r.status_code == 401 and r.json()["ok"] is False
        assert c.post("/rx14/wrong/v1/dtc/analyze", files=rom(synthetic_bin)).status_code == 401
        assert c.post(f"/rx14/{key}/v1/dtc/analyze", files=rom(synthetic_bin)).json()["dtcs_total"] == 2
        r = c.post("/v1/features/detect", files=rom(synthetic_bin), headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 200 and "synthetic_fan" in r.json()["available"]
