"""Immutable, content-addressed BIN vault: data/vault/{sha256[0:2]}/{sha256}.bin.

Originals are never modified in place. Writes go to a temp file, are hash-verified, then atomically renamed.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.errors import AktoolError

_SHA_HEX = set("0123456789abcdef")


@dataclass(frozen=True)
class StoredBlob:
    sha256: str
    md5: str
    size: int
    path: Path
    created: bool


class BinVault:
    def __init__(self, root: Path, max_bytes: int):
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or not set(sha256) <= _SHA_HEX:
            raise AktoolError("INVALID_SHA256", "sha256 must be 64 lowercase hex characters", field="sha256")
        path = (self.root / sha256[:2] / f"{sha256}.bin").resolve()
        if self.root.resolve() not in path.parents:
            raise AktoolError("PATH_OUTSIDE_VAULT", "resolved path escapes the vault")
        return path

    def put(self, data: bytes) -> StoredBlob:
        if not data:
            raise AktoolError("EMPTY_FILE", "BIN file is empty", field="file")
        if len(data) > self.max_bytes:
            raise AktoolError("FILE_TOO_LARGE", "BIN file exceeds the configured size limit", field="file",
                              details={"size": len(data), "max_bytes": self.max_bytes}, status_code=413)
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        target = self.path_for(sha256)
        if target.exists():
            self._verify(target, sha256)
            return StoredBlob(sha256, md5, len(data), target, created=False)

        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".incoming-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            self._verify(Path(tmp_name), sha256)
            os.chmod(tmp_name, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            os.replace(tmp_name, target)
        except BaseException:
            if os.path.exists(tmp_name):
                os.chmod(tmp_name, stat.S_IWUSR | stat.S_IRUSR)
                os.unlink(tmp_name)
            raise
        return StoredBlob(sha256, md5, len(data), target, created=True)

    def read(self, sha256: str) -> bytes:
        path = self.path_for(sha256)
        if not path.exists():
            raise AktoolError("BLOB_MISSING", "BIN is not present in the vault", details={"sha256": sha256},
                              status_code=404)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise AktoolError("VAULT_CORRUPTED", "stored BIN no longer matches its hash", details={"sha256": sha256},
                              status_code=500)
        return data

    def read_range(self, sha256: str, offset: int, length: int, max_length: int) -> bytes:
        if offset < 0 or length <= 0:
            raise AktoolError("INVALID_RANGE", "offset must be >= 0 and length > 0",
                              details={"offset": offset, "length": length})
        if length > max_length:
            raise AktoolError("RANGE_TOO_LARGE", "requested range exceeds the per-request limit",
                              details={"length": length, "max_length": max_length})
        path = self.path_for(sha256)
        size = path.stat().st_size
        if offset + length > size:
            raise AktoolError("OFFSET_OUT_OF_RANGE", "range extends past the end of the file",
                              details={"offset": offset, "length": length, "file_size": size})
        with path.open("rb") as fh:
            fh.seek(offset)
            return fh.read(length)

    @staticmethod
    def _verify(path: Path, sha256: str) -> None:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != sha256:
            raise AktoolError("HASH_MISMATCH", "written BIN failed hash verification", status_code=500)
