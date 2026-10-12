"""BIN fingerprints (FR-04): fixed-size block hashes plus the identifier strings a file carries.

Block hashes find files that share most of their content (a variant, a tune of the same software), and the
reverse index finds them without reading every stored BIN. Identifiers (part numbers, Bosch hardware and
software numbers, ECU version strings) link files whose bytes moved.
"""

from __future__ import annotations

import hashlib
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import FingerprintBlock, FirmwareBlob, FirmwareFingerprint
from core.vault import BinVault

BLOCK_SIZE = 4096
MAX_IDENTIFIERS = 32

_IDENTIFIER_PATTERNS = (
    re.compile(rb"(?<![0-9A-Za-z])0261[0-9]{6}(?![0-9A-Za-z])"),  # Bosch hardware number
    re.compile(rb"(?<![0-9A-Za-z])1037[0-9]{6}(?![0-9A-Za-z])"),  # Bosch software number
    re.compile(rb"(?<![0-9A-Za-z])[0-9][A-Z0-9]{2}9[0-9]{5}[A-Z]{0,3}(?![0-9A-Za-z])"),  # VAG part, e.g. 8D0907551M
    re.compile(rb"[0-9A-Z]{1,4}/[0-9]{1,2}/(?:ME|MED|MEV|MEVD|EDC|MD|MG|SIMOS)[0-9A-Z.]*/[\x20-\x7e]{0,48}"),
)


def block_hashes(data: bytes, block_size: int = BLOCK_SIZE) -> list[str]:
    """One 16-hex hash per block; '' for a block that is a single repeated byte (padding matches everything)."""
    out = []
    for start in range(0, len(data), block_size):
        block = data[start:start + block_size]
        uniform = block.count(block[:1]) == len(block)
        out.append("" if uniform else hashlib.blake2b(block, digest_size=8).hexdigest())
    return out


def identifiers(data: bytes) -> list[str]:
    found: list[str] = []
    for pattern in _IDENTIFIER_PATTERNS:
        for match in pattern.finditer(data):
            value = match.group().decode("ascii").rstrip(" /")
            if value not in found:
                found.append(value)
            if len(found) >= MAX_IDENTIFIERS:
                return found
    return found


def ensure(session: Session, blob: FirmwareBlob, data: bytes) -> FirmwareFingerprint:
    fp = session.get(FirmwareFingerprint, blob.id)
    if fp is not None:
        return fp
    hashes = block_hashes(data)
    fp = FirmwareFingerprint(blob_id=blob.id, block_size=BLOCK_SIZE, blocks=",".join(hashes),
                             identifiers=json.dumps(identifiers(data)))
    session.add(fp)
    first: dict[str, int] = {}
    for block_no, h in enumerate(hashes):
        if h and h not in first:
            first[h] = block_no
    session.add_all(FingerprintBlock(blob_id=blob.id, block_no=n, hash=h) for h, n in first.items())
    session.flush()
    return fp


def backfill(session: Session, vault: BinVault) -> int:
    """Fingerprint every stored BIN that has none yet (files stored before fingerprints existed)."""
    missing = session.scalars(select(FirmwareBlob).where(
        ~FirmwareBlob.id.in_(select(FirmwareFingerprint.blob_id)))).all()
    for blob in missing:
        ensure(session, blob, vault.read(blob.sha256))
    if missing:
        session.commit()
    return len(missing)
