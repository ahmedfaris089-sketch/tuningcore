import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from core.api import create_app
from core.settings import Settings
from tests.conftest import upload

EXAMPLES = Path(__file__).resolve().parents[1] / "schemas" / "examples"


def test_health(client):
    body = client.get("/api/v1/health").json()
    assert body["status"] == "ok" and body["mode"] == "local"


def test_upload_twice_returns_same_record(client, synthetic_bin):
    first = upload(client, synthetic_bin, software_id="SYN0001", calibration_id="CAL0001", file_role="original")
    assert first.status_code == 201 and first.json()["created"] is True
    assert first.json()["sha256"] == hashlib.sha256(synthetic_bin).hexdigest()
    second = upload(client, synthetic_bin, name="renamed.bin")
    assert second.status_code == 200 and second.json()["created"] is False
    assert second.json()["id"] == first.json()["id"]


def test_stock_modified_link_and_cycle_rejected(client, synthetic_bin):
    stock = upload(client, synthetic_bin, file_role="original").json()
    modified_bytes = bytearray(synthetic_bin)
    modified_bytes[0x1000] = 0x00
    mod = upload(client, bytes(modified_bytes), name="mod.bin", file_role="modified",
                 parent_firmware_id=str(stock["id"])).json()
    assert mod["relations"][0] == {"id": mod["relations"][0]["id"], "source_id": mod["id"], "target_id": stock["id"],
                                   "relation_type": "modified_from", "confidence": 1.0}
    cycle = client.post(f"/api/v1/firmware/{stock['id']}/relations",
                        json={"target_id": mod["id"], "relation_type": "modified_from"})
    assert cycle.status_code == 400 and cycle.json()["error"]["code"] == "RELATION_CYCLE"
    self_link = client.post(f"/api/v1/firmware/{stock['id']}/relations",
                            json={"target_id": stock["id"], "relation_type": "variant_of"})
    assert self_link.json()["error"]["code"] == "SELF_RELATION"


def test_original_bytes_unchanged_after_modified_upload(client, synthetic_bin, settings):
    stock = upload(client, synthetic_bin).json()
    upload(client, synthetic_bin[:-1] + b"\x00", name="mod.bin", parent_firmware_id=str(stock["id"]))
    stored = (settings.vault_dir / stock["sha256"][:2] / f"{stock['sha256']}.bin").read_bytes()
    assert stored == synthetic_bin


def test_patch_and_search(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    patched = client.patch(f"/api/v1/firmware/{fw['id']}", json={"software_id": "SYN0001", "ecu_family": "synthetic_test"})
    assert patched.json()["software_id"] == "SYN0001"
    hits = client.get("/api/v1/firmware", params={"q": "SYN0001"}).json()
    assert [h["id"] for h in hits] == [fw["id"]]
    assert client.get("/api/v1/firmware", params={"q": fw["sha256"]}).json()[0]["id"] == fw["id"]


def test_read_bytes_range(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    body = client.get(f"/api/v1/firmware/{fw['id']}/bytes", params={"offset": 0x1000, "length": 1}).json()
    assert body["bytes"] == "01" and body["offset_hex"] == "0x1000"
    past = client.get(f"/api/v1/firmware/{fw['id']}/bytes", params={"offset": len(synthetic_bin) - 1, "length": 4})
    assert past.json()["error"]["code"] == "OFFSET_OUT_OF_RANGE"


def test_validate_endpoint_checks_bin(client, synthetic_bin):
    fw = upload(client, synthetic_bin).json()
    record = json.loads((EXAMPLES / "valid" / "function_map_table.json").read_text())
    ok = client.post("/api/v1/json/validate", json={"record": record, "firmware_id": fw["id"]}).json()
    assert ok["valid"] and ok["binary_checked"]
    record["original_bytes"] = "FF" + record["original_bytes"][2:]
    bad = client.post("/api/v1/json/validate", json={"record": record, "firmware_id": fw["id"]}).json()
    assert not bad["valid"] and "ORIGINAL_BYTES_MISMATCH" in [e["code"] for e in bad["errors"]]


def test_unknown_firmware_is_404(client):
    r = client.get("/api/v1/firmware/999")
    assert r.status_code == 404 and r.json()["error"]["code"] == "FIRMWARE_NOT_FOUND"


def test_server_mode_requires_api_key(tmp_path, synthetic_bin):
    settings = Settings(mode="server", data_dir=tmp_path / "srv", api_key="secret")
    with TestClient(create_app(settings)) as c:
        assert c.get("/api/v1/firmware").status_code == 401
        assert c.get("/api/v1/firmware", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/v1/firmware", headers={"X-API-Key": "secret"}).status_code == 200


def test_migrations_are_idempotent(settings):
    create_app(settings)
    create_app(settings)


def test_data_dir_with_percent_encoded_url(tmp_path):
    # Windows paths become "sqlite:///C%3A/..." in the engine URL; "%" must not break Alembic.
    settings = Settings(mode="local", data_dir=tmp_path / "100% data")
    with TestClient(create_app(settings)) as c:
        assert c.get("/api/v1/health").status_code == 200
