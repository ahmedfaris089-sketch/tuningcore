import copy
import hashlib
import json
import random
import struct

import pytest

from core.fingerprint import block_hashes, identifiers
from tests.conftest import ROOT, upload
from tests.test_kp_binary import MAP_AT, X_AT, Y_AT, kp_file

SWITCH_AT = 0x1000


def base_bin() -> bytes:
    """64 KiB of seeded random bytes (no repeating pattern), an erased block, a part number and an on/off byte."""
    buf = bytearray(random.Random(7).randbytes(0x10000))
    buf[0x8000:0x9000] = b"\xff" * 0x1000
    buf[0x200:0x20A] = b"8D0907551M"
    buf[SWITCH_AT] = 0x01
    return bytes(buf)


def tuned(data: bytes) -> bytes:
    """Same file with the KP map's values changed, axes untouched."""
    buf = bytearray(data)
    for i in range(6):
        struct.pack_into("<h", buf, MAP_AT + 2 * i, 100 * (i + 1))
    return bytes(buf)


def shifted(data: bytes, by: int) -> bytes:
    return bytes(random.Random(9).randbytes(by)) + data[:-by]


def switch_record(data: bytes) -> dict:
    with open(ROOT / "schemas" / "examples" / "valid" / "function_on_off.json") as fh:
        r = json.load(fh)
    r.update(record_id="test-switch", sha256=hashlib.sha256(data).hexdigest(), md5=hashlib.md5(data).hexdigest(),
             file_size=len(data), file_offset=SWITCH_AT, end_file_offset=SWITCH_AT + 1, original_bytes="01",
             reviewer="tester")
    for e in r["evidence"]:
        e["file_offset"] = SWITCH_AT
    return r


@pytest.fixture
def stock(client):
    """A stock BIN with an approved KP map and an approved on/off switch."""
    data = base_bin()
    fw = upload(client, data, software_id="SW1", calibration_id="CAL1").json()
    done = client.post("/api/v1/sources/import/kp", files={"file": ("maps.kp", kp_file())},
                       data={"firmware_id": fw["id"], "apply": "true"}).json()
    map_id = done["items"][0]["record_id"]
    assert client.post(f"/api/v1/review/{map_id}/accept", json={"revision": 1}).status_code == 200
    r = client.post("/api/v1/definitions", json={"record": switch_record(data)})
    assert r.status_code == 201, r.json()
    return client, fw, data, map_id


def transfer(client, target_id, source_id, apply=False, **extra):
    return client.post(f"/api/v1/firmware/{target_id}/transfer",
                       json={"source_firmware_id": source_id, "apply": apply, **extra})


def by_source(result):
    return {i["source_record_id"]: i for i in result["items"]}


def test_fingerprint_skips_padding_and_reads_identifiers():
    data = base_bin()
    hashes = block_hashes(data)
    assert len(hashes) == 16 and hashes[8] == "" and all(h for n, h in enumerate(hashes) if n != 8)
    blob = b"\x00HW 0261207881 SW 1037360000\x00" + b"40/1/ME7.1/5/6005.01//22m/\x00"
    assert identifiers(blob + b"x8D0907551M ") == ["0261207881", "1037360000", "40/1/ME7.1/5/6005.01//22m"]
    assert identifiers(b"A8D0907551M") == []


def test_identify_finds_variant_and_skips_unrelated(stock):
    client, fw, data, _ = stock
    other = upload(client, tuned(data), name="tuned.bin").json()
    upload(client, bytes(random.Random(3).randbytes(0x10000)), name="other.bin")
    out = client.get(f"/api/v1/firmware/{other['id']}/identify").json()
    assert out["match_level"] == "variant" and out["identifiers"] == ["8D0907551M"]
    assert out["informative_blocks"] == 15
    [c] = out["candidates"]
    assert c["firmware_id"] == fw["id"] and c["level"] == "variant"
    assert c["same_offset_block_ratio"] == pytest.approx(14 / 15, abs=1e-4)
    assert c["differing_bytes"] == sum(1 for a, b in zip(data, tuned(data)) if a != b)
    assert (c["trusted_records"], c["draft_records"]) == (2, 0)
    assert client.get(f"/api/v1/firmware/{fw['id']}/identify").json()["match_level"] == "exact"


def test_identify_shifted_file_is_family_candidate(stock):
    client, fw, data, _ = stock
    moved = upload(client, shifted(data, 0x123), name="moved.bin").json()
    out = client.get(f"/api/v1/firmware/{moved['id']}/identify").json()
    assert out["match_level"] == "family_candidate"
    assert out["candidates"][0]["shared_identifiers"] == ["8D0907551M"]


def test_transfer_to_tuned_file_uses_axes_and_reads_new_values(stock):
    client, fw, data, map_id = stock
    target = upload(client, tuned(data), name="tuned.bin").json()
    preview = transfer(client, target["id"], fw["id"]).json()
    assert preview["applied"] is False and preview["would_create"] == 2
    assert preview["same_layout"] is True
    assert preview["by_method"] == {"identical_bytes": 1, "relocated": 0, "axes_match": 1, "same_layout": 0}
    assert client.get("/api/v1/review/queue").json() == []

    done = transfer(client, target["id"], fw["id"], apply=True).json()
    assert done["created"] == 2
    item = by_source(done)[map_id]
    assert item["method"] == "axes_match" and item["delta"] == 0
    rev = client.get(f"/api/v1/definitions/{item['record_id']}").json()["revisions"][0]
    p = rev["payload"]
    assert rev["binary_verified"] is True and p["review_state"] == "draft" and p["sha256"] == target["sha256"]
    assert p["original_physical_values"] == [[50.0, 100.0, 150.0], [200.0, 250.0, 300.0]]
    assert p["confidence"] == 0.6  # never above the source record's own confidence
    assert p["x_transfer"]["source_record_id"] == map_id and p["evidence"][0]["source_type"] == "aktool_json"
    queued = {i["record_id"] for i in client.get("/api/v1/review/queue").json()}
    assert queued == {i["record_id"] for i in done["items"]}

    again = transfer(client, target["id"], fw["id"], apply=True).json()
    assert again["unchanged"] == 2 and again["created"] == 0


def test_transfer_to_shifted_file_moves_offsets_and_axes(stock):
    client, fw, data, map_id = stock
    target = upload(client, shifted(data, 0x123), name="moved.bin").json()
    done = transfer(client, target["id"], fw["id"], apply=True).json()
    assert done["created"] == 2 and done["by_method"]["relocated"] == 2
    item = by_source(done)[map_id]
    assert item["delta"] == 0x123 and item["file_offset"] == MAP_AT + 0x123
    p = client.get(f"/api/v1/definitions/{item['record_id']}").json()["revisions"][0]["payload"]
    assert [a["file_offset"] for a in p["axes"]] == [X_AT + 0x123, Y_AT + 0x123]
    assert by_source(done)["test-switch"]["file_offset"] == SWITCH_AT + 0x123


def changed_axes(data: bytes) -> bytearray:
    buf = bytearray(tuned(data))
    buf[X_AT] ^= 0xFF  # an axis changed too, so the axes no longer prove where the map is
    buf[SWITCH_AT - 4] ^= 0xFF  # context changed and one byte is too short to search on its own
    return buf


def test_same_layout_variant_rereads_map_and_axes(stock):
    client, fw, data, map_id = stock
    buf = changed_axes(data)
    target = upload(client, bytes(buf), name="changed.bin").json()
    done = transfer(client, target["id"], fw["id"], apply=True).json()
    out = by_source(done)
    assert done["same_layout"] is True and out[map_id]["method"] == "same_layout"
    p = client.get(f"/api/v1/definitions/{out[map_id]['record_id']}").json()["revisions"][0]["payload"]
    assert p["confidence"] == 0.5 and p["axes"][0]["values"][0] == buf[X_AT] * 40.0
    assert p["original_physical_values"][0] == [50.0, 100.0, 150.0]
    assert (out["test-switch"]["action"], out["test-switch"]["reason"]) == ("skipped", "NOT_FOUND")


def test_transfer_skips_what_it_cannot_locate(stock):
    client, fw, data, map_id = stock
    buf = changed_axes(data)
    buf[0xA000:] = random.Random(5).randbytes(0x6000)  # different software: layout no longer shared
    target = upload(client, bytes(buf), name="other_sw.bin").json()
    result = transfer(client, target["id"], fw["id"]).json()
    out = by_source(result)
    assert result["same_layout"] is False
    assert (out[map_id]["action"], out[map_id]["reason"]) == ("skipped", "NOT_FOUND")
    assert (out["test-switch"]["action"], out["test-switch"]["reason"]) == ("skipped", "NOT_FOUND")


def test_transfer_reports_existing_records_and_refuses_bad_requests(stock):
    client, fw, data, map_id = stock
    target = upload(client, tuned(data), name="tuned.bin").json()
    client.post("/api/v1/sources/import/kp", files={"file": ("maps.kp", kp_file())},
                data={"firmware_id": target["id"], "apply": "true"})
    out = by_source(transfer(client, target["id"], fw["id"]).json())
    assert out[map_id]["action"] == "exists" and out[map_id]["existing_record_id"].startswith("kp-")

    r = transfer(client, fw["id"], fw["id"])
    assert r.status_code == 400 and r.json()["error"]["code"] == "SAME_FIRMWARE"
    r = transfer(client, target["id"], fw["id"], record_ids=["nope"])
    assert r.status_code == 400 and r.json()["error"]["code"] == "NOT_TRUSTED_SOURCE_RECORDS"
    only = transfer(client, target["id"], fw["id"], record_ids=["test-switch"]).json()
    assert [i["source_record_id"] for i in only["items"]] == ["test-switch"]


def test_drafts_on_the_source_are_not_transferred(client):
    data = base_bin()
    fw = upload(client, data).json()
    client.post("/api/v1/sources/import/kp", files={"file": ("maps.kp", kp_file())},
                data={"firmware_id": fw["id"], "apply": "true"})
    target = upload(client, tuned(data), name="tuned.bin").json()
    out = transfer(client, target["id"], fw["id"]).json()
    assert out["source_trusted_records"] == 0 and out["items"] == []
