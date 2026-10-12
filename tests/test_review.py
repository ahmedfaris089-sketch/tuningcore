import pytest

from tests.conftest import upload
from tests.test_kp_binary import kp_file


@pytest.fixture
def drafts(client, synthetic_bin):
    """One KP map imported as a draft for the synthetic BIN."""
    fw = upload(client, synthetic_bin, software_id="SYN0001", calibration_id="CAL0001").json()
    done = client.post("/api/v1/sources/import/kp", files={"file": ("maps.kp", kp_file())},
                       data={"firmware_id": fw["id"], "apply": "true"}).json()
    assert done["created"] == 1
    return client, done["items"][0]["record_id"], fw


def latest(client, record_id):
    return client.get(f"/api/v1/definitions/{record_id}").json()["revisions"][-1]


def test_queue_lists_drafts_with_filters(drafts):
    client, record_id, fw = drafts
    items = client.get("/api/v1/review/queue").json()
    assert [i["record_id"] for i in items] == [record_id]
    assert items[0]["evidence_sources"] == ["binary_check", "kp"] and items[0]["revision"] == 1
    assert client.get("/api/v1/review/queue", params={"category": "bosch_dtc"}).json() == []
    assert len(client.get("/api/v1/review/queue", params={"sha256": fw["sha256"]}).json()) == 1
    assert len(client.get("/api/v1/review/queue", params={"q": "torque"}).json()) == 1


def test_accept_rechecks_bin_and_leaves_queue(drafts):
    client, record_id, _ = drafts
    r = client.post(f"/api/v1/review/{record_id}/accept", json={"revision": 1, "note": "matches WinOLS"})
    assert r.status_code == 200, r.json()
    assert r.json()["review_state"] == "approved" and r.json()["binary_verified"] is True
    rev = latest(client, record_id)
    assert rev["revision"] == 2 and rev["payload"]["reviewer"] == "local-user"
    assert rev["payload"]["validation_steps"][-1] == "human review"
    assert client.get("/api/v1/review/queue").json() == []
    assert client.post("/api/v1/exports", json={"record_id": record_id}).status_code == 201
    history = client.get(f"/api/v1/review/{record_id}/history").json()
    assert [(h["decision"], h["from_revision"], h["to_revision"], h["note"]) for h in history] == [
        ("accept", 1, 2, "matches WinOLS")]


def test_stale_and_repeated_decisions_are_refused(drafts):
    client, record_id, _ = drafts
    r = client.post(f"/api/v1/review/{record_id}/accept", json={"revision": 5})
    assert r.status_code == 409 and r.json()["error"]["code"] == "STALE_REVIEW"
    client.post(f"/api/v1/review/{record_id}/accept", json={"revision": 1})
    r = client.post(f"/api/v1/review/{record_id}/accept", json={"revision": 2})
    assert r.status_code == 409 and r.json()["error"]["code"] == "NOT_A_DRAFT"


def test_edit_records_changed_fields(drafts):
    client, record_id, _ = drafts
    r = client.post(f"/api/v1/review/{record_id}/edit",
                    json={"revision": 1, "changes": {"name": "Torque limiter (corrected)", "unit": "Nm"},
                          "note": "renamed"})
    assert r.status_code == 200, r.json()
    assert r.json()["changed_fields"] == ["name"] and r.json()["review_state"] == "approved"
    assert latest(client, record_id)["payload"]["name"] == "Torque limiter (corrected)"
    assert client.get(f"/api/v1/review/{record_id}/history").json()[0]["changed_fields"] == ["name"]


def test_edit_can_stay_draft(drafts):
    client, record_id, _ = drafts
    r = client.post(f"/api/v1/review/{record_id}/edit",
                    json={"revision": 1, "changes": {"description": "needs a second look"}, "approve": False})
    assert r.json()["review_state"] == "draft"
    assert [i["revision"] for i in client.get("/api/v1/review/queue").json()] == [2]


def test_edit_cannot_touch_identity_or_break_bytes(drafts):
    client, record_id, _ = drafts
    r = client.post(f"/api/v1/review/{record_id}/edit", json={"revision": 1, "changes": {"sha256": "0" * 64}})
    assert r.status_code == 400 and r.json()["error"]["code"] == "FIELD_NOT_EDITABLE"
    original = latest(client, record_id)["payload"]["original_bytes"]
    wrong = "00" + original[2:] if not original.startswith("00") else "FF" + original[2:]
    r = client.post(f"/api/v1/review/{record_id}/edit",
                    json={"revision": 1, "changes": {"original_bytes": wrong, "original_raw_bytes": wrong}})
    assert r.status_code == 422 and r.json()["error"]["code"] == "RECORD_INVALID"
    assert latest(client, record_id)["revision"] == 1 and client.get(f"/api/v1/review/{record_id}/history").json() == []


def test_reject_needs_a_reason_and_survives_reimport(drafts):
    client, record_id, fw = drafts
    r = client.post(f"/api/v1/review/{record_id}/reject", json={"revision": 1})
    assert r.status_code == 400 and r.json()["error"]["code"] == "NOTE_REQUIRED"
    r = client.post(f"/api/v1/review/{record_id}/reject", json={"revision": 1, "note": "wrong axis"})
    assert r.json()["review_state"] == "deprecated"
    assert client.get("/api/v1/review/queue").json() == []
    again = client.post("/api/v1/sources/import/kp", files={"file": ("maps.kp", kp_file())},
                        data={"firmware_id": fw["id"], "apply": "true"}).json()
    assert again["unchanged"] == 1 and again["rejected"] == 0 and again["created"] == 0
