from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core.api import create_app
from core.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_BIN = ROOT / "fixtures" / "synthetic" / "synthetic_ecu.bin"


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def synthetic_bin() -> bytes:
    return SYNTHETIC_BIN.read_bytes()


def upload(client, data: bytes, name="stock.bin", **form):
    return client.post("/api/v1/firmware", files={"file": (name, data, "application/octet-stream")}, data=form)
