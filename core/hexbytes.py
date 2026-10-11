"""Canonical hex byte strings: 'AA BB 00 1F'."""

from __future__ import annotations

import re

_HEX_RE = re.compile(r"^[0-9A-Fa-f]{2}( [0-9A-Fa-f]{2})*$")


def to_hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def from_hex(text: str) -> bytes:
    if not _HEX_RE.match(text):
        raise ValueError(f"not a canonical hex byte string: {text[:40]!r}")
    return bytes.fromhex(text.replace(" ", ""))


def normalize(text: str) -> str:
    """Accept loose input (no spaces, 0x prefixes, commas) and return canonical uppercase form."""
    cleaned = re.sub(r"0x", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s,;:-]", "", cleaned)
    if len(cleaned) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", cleaned):
        raise ValueError(f"cannot normalize hex input: {text[:40]!r}")
    return to_hex(bytes.fromhex(cleaned))
