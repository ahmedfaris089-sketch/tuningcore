import copy
import json
from pathlib import Path

import pytest

from core.jsonfactory import canonicalize, export_filename, payload_hash
from tests.conftest import upload

VALID = Path(__file__).resolve().parents[1] / "schemas" / "examples" / "valid"


def example(category: str) -> dict:
    return json.loads((VALID / f"{category}.json").read_text())


@pytest.fixture
def with_bin(client, synthetic_bin):
    upload(client, synthetic_bin, software_id="SYN0001", calibration_id="CAL0001")
    return client


def test_filename_convention():
    rec = example("function_map_table")
    assert export_filename(rec) == "Synthetic_torque_limit_function_map_table_SYN0001_CAL0001_r1.json"
    rec["name"] = "مروحة"  # non-latin name falls back to the concept key
    rec["map_key"] = "fan_map"
    assert export_filename(rec).startswith("fan_map_function_map_table")


def test_canonical_hash_ignores_hex_case_and_key_order():
    rec = example("function_on_off")
    lower = copy.deepcopy(rec)
    lower["original_bytes"] = lower["original_bytes"].lower()
    reordered = dict(reversed(list(rec.items())))
    assert payload_hash(canonicalize(lower)) == payload_hash(canonicalize(rec)) == payload_hash(canonicalize(reordered))


@pytest.mark.parametrize("category", ["function_on_off", "function_map_table", "bosch_dtc", "non_bosch_dtc"])
def test_create_export_reimport_round_trip(with_bin, settings, category):
    c = with_bin
    rec = example(category)
    created = c.post("/api/v1/definitions", json={"record": rec})
    assert created.status_code == 201, created.json()
    assert created.json()["binary_verified"] is True

    exported = c.post("/api/v1/exports", json={"record_id": rec["record_id"]})
    assert exported.status_code == 201, exported.json()
    text = Path(exported.json()["path"]).read_text(encoding="utf-8")
    assert json.loads(text) == canonicalize(rec)

    again = c.post("/api/v1/json/import", json={"record": json.loads(text), "apply": True}).json()
    assert again["action"] == "unchanged" and again["payload_hash"] == created.json()["payload_hash"]


def test_revision_sequence_and_immutability(with_bin):
    c = with_bin
    rec = example("function_on_off")
    c.post("/api/v1/definitions", json={"record": rec})
    dup = c.post("/api/v1/definitions", json={"record": rec})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "RECORD_EXISTS"

    r2 = {**rec, "revision": 2, "description": "clarified", "updated_at": "2026-10-12T00:00:00Z"}
    ok = c.post(f"/api/v1/definitions/{rec['record_id']}/revisions", json={"record": r2})
    assert ok.status_code == 201 and ok.json()["revision"] == 2
    skip = c.post(f"/api/v1/definitions/{rec['record_id']}/revisions", json={"record": {**r2, "revision": 4}})
    assert skip.json()["error"]["code"] == "REVISION_SEQUENCE"

    body = c.get(f"/api/v1/definitions/{rec['record_id']}").json()
    assert [r["revision"] for r in body["revisions"]] == [1, 2]
    assert body["revisions"][0]["payload"]["description"] == rec["description"]

    conflict = c.post("/api/v1/json/import", json={"record": {**rec, "description": "edited in place"}}).json()
    assert conflict["action"] == "reject" and conflict["errors"][0]["code"] == "REVISION_CONFLICT"


def test_wrong_bytes_never_stored(with_bin):
    rec = example("function_on_off")
    rec.update(original_bytes="00", on_bytes="01", off_bytes="00")  # BIN actually holds 01
    r = with_bin.post("/api/v1/definitions", json={"record": rec})
    assert r.status_code == 422
    codes = [e["code"] for e in r.json()["error"]["details"]["errors"]]
    assert "ORIGINAL_BYTES_MISMATCH" in codes


def test_approved_record_requires_bin_in_vault(client):
    r = client.post("/api/v1/definitions", json={"record": example("bosch_dtc")})
    assert r.status_code == 422
    assert "TRUSTED_NEEDS_BIN" in [e["code"] for e in r.json()["error"]["details"]["errors"]]


def test_draft_without_bin_is_allowed_but_not_exportable(client):
    rec = {**example("function_on_off"), "review_state": "draft", "reviewer": None}
    created = client.post("/api/v1/definitions", json={"record": rec}).json()
    assert created["binary_verified"] is False
    assert "BIN_NOT_IN_VAULT" in [w["code"] for w in created["warnings"]]
    preview = client.post("/api/v1/exports/preview", json={"record_id": rec["record_id"]}).json()
    assert not preview["valid"] and "NOT_APPROVED" in [e["code"] for e in preview["errors"]]
    blocked = client.post("/api/v1/exports", json={"record_id": rec["record_id"]})
    assert blocked.status_code == 422 and blocked.json()["error"]["code"] == "EXPORT_BLOCKED"


def test_import_preview_does_not_write(with_bin):
    rec = example("non_bosch_dtc")
    preview = with_bin.post("/api/v1/json/import", json={"record": rec}).json()
    assert preview["action"] == "create" and preview["valid"]
    assert with_bin.get(f"/api/v1/definitions/{rec['record_id']}").status_code == 404


def test_search_definitions(with_bin):
    with_bin.post("/api/v1/definitions", json={"record": example("bosch_dtc")})
    with_bin.post("/api/v1/definitions", json={"record": example("function_map_table")})
    assert [d["concept_key"] for d in with_bin.get("/api/v1/definitions", params={"q": "P0123"}).json()] == ["P0123"]
    assert len(with_bin.get("/api/v1/definitions", params={"category": "function_map_table"}).json()) == 1
