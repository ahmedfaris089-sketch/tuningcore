"""Runtime settings. MODE=local binds to 127.0.0.1 with no auth; MODE=server requires an API key."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    mode: str = "local"
    data_dir: Path = Path("data")
    host: str = "127.0.0.1"
    port: int = 8765
    max_bin_bytes: int = 64 * 1024 * 1024
    max_range_bytes: int = 64 * 1024
    api_key: str | None = None
    # romHEX14 cloud API: "require" refuses to return a modified BIN unless a checksum corrector is
    # registered for its family; "client" returns it uncorrected and leaves correction to romHEX14.
    rx14_checksum: str = "require"
    schema_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "schemas")

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vault"

    @property
    def db_url(self) -> str:
        return f"sqlite:///{(self.data_dir / 'aktool.db').as_posix()}"

    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.environ.get("AKTOOL_MODE", "local")
        if mode not in ("local", "server"):
            raise ValueError(f"AKTOOL_MODE must be 'local' or 'server', got {mode!r}")
        api_key = os.environ.get("AKTOOL_API_KEY") or None
        if mode == "server" and not api_key:
            raise ValueError("AKTOOL_API_KEY is required when AKTOOL_MODE=server")
        rx14_checksum = os.environ.get("AKTOOL_RX14_CHECKSUM", "require")
        if rx14_checksum not in ("require", "client"):
            raise ValueError(f"AKTOOL_RX14_CHECKSUM must be 'require' or 'client', got {rx14_checksum!r}")
        return cls(
            mode=mode,
            data_dir=Path(os.environ.get("AKTOOL_DATA_DIR", "data")),
            host=os.environ.get("AKTOOL_HOST", "127.0.0.1" if mode == "local" else "0.0.0.0"),
            port=int(os.environ.get("AKTOOL_PORT", "8765")),
            max_bin_bytes=int(os.environ.get("AKTOOL_MAX_BIN_MB", "64")) * 1024 * 1024,
            api_key=api_key,
            rx14_checksum=rx14_checksum,
        )
