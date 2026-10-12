"""Checksum correctors per ECU family.

A modified BIN is only handed out when a corrector is registered for its family (or when the operator
explicitly leaves correction to the client tool). None are registered yet: real algorithms will come
from romHEX14's checksum plugins run as a separate program.
"""

from __future__ import annotations

from typing import Callable

Corrector = Callable[[bytes], bytes]


class ChecksumRegistry:
    def __init__(self) -> None:
        self._by_family: dict[str, Corrector] = {}

    def register(self, family: str, corrector: Corrector) -> None:
        self._by_family[family.strip().lower()] = corrector

    def get(self, family: str | None) -> Corrector | None:
        if not family:
            return None
        return self._by_family.get(family.strip().lower())

    def families(self) -> list[str]:
        return sorted(self._by_family)
