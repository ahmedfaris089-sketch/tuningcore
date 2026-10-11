import hashlib
import os
import stat

import pytest

from core.errors import AktoolError
from core.vault import BinVault


def test_put_is_content_addressed_and_deduplicated(tmp_path):
    vault = BinVault(tmp_path, max_bytes=1024)
    first = vault.put(b"abc")
    second = vault.put(b"abc")
    assert first.created and not second.created
    assert first.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert first.path == tmp_path.resolve() / first.sha256[:2] / f"{first.sha256}.bin"
    assert len(list(tmp_path.rglob("*.bin"))) == 1


def test_stored_original_is_read_only(tmp_path):
    blob = BinVault(tmp_path, max_bytes=1024).put(b"original")
    assert not os.stat(blob.path).st_mode & stat.S_IWUSR


def test_limits_and_ranges(tmp_path):
    vault = BinVault(tmp_path, max_bytes=8)
    with pytest.raises(AktoolError) as e:
        vault.put(b"x" * 9)
    assert e.value.code == "FILE_TOO_LARGE"
    with pytest.raises(AktoolError) as e:
        vault.put(b"")
    assert e.value.code == "EMPTY_FILE"
    blob = vault.put(b"01234567")
    assert vault.read_range(blob.sha256, 2, 3, max_length=16) == b"234"
    with pytest.raises(AktoolError) as e:
        vault.read_range(blob.sha256, 6, 4, max_length=16)
    assert e.value.code == "OFFSET_OUT_OF_RANGE"


def test_rejects_path_tricks(tmp_path):
    vault = BinVault(tmp_path, max_bytes=8)
    with pytest.raises(AktoolError):
        vault.path_for("../" + "a" * 61)


def test_detects_tampering(tmp_path):
    vault = BinVault(tmp_path, max_bytes=64)
    blob = vault.put(b"original")
    os.chmod(blob.path, stat.S_IWUSR | stat.S_IRUSR)
    blob.path.write_bytes(b"tampered")
    with pytest.raises(AktoolError) as e:
        vault.read(blob.sha256)
    assert e.value.code == "VAULT_CORRUPTED"
