"""Checks a record against the actual BIN bytes. This is the core anti-hallucination gate."""

from __future__ import annotations

import hashlib
from typing import Any

from core.hexbytes import from_hex, to_hex
from core.validators.contract import Issue


def check_against_bin(record: dict[str, Any], data: bytes) -> list[Issue]:
    issues: list[Issue] = []
    if len(data) != record["file_size"]:
        issues.append(Issue("error", "FILE_SIZE_MISMATCH", "$.file_size",
                            f"record says {record['file_size']} bytes, BIN has {len(data)}"))
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        issues.append(Issue("error", "SHA256_MISMATCH", "$.sha256", "record sha256 does not match the BIN"))
    if hashlib.md5(data).hexdigest() != record["md5"]:
        issues.append(Issue("error", "MD5_MISMATCH", "$.md5", "record md5 does not match the BIN"))

    def compare(path: str, offset: int, expected_hex: str) -> None:
        expected = from_hex(expected_hex)
        actual = data[offset:offset + len(expected)]
        if len(actual) < len(expected):
            issues.append(Issue("error", "OFFSET_OUT_OF_RANGE", path, f"offset {offset} + {len(expected)} is past the end of the BIN"))
        elif actual != expected:
            issues.append(Issue("error", "ORIGINAL_BYTES_MISMATCH", path,
                                f"at offset {offset} expected {expected_hex[:47]} but BIN has {to_hex(actual)[:47]}"))

    compare("$.original_bytes", record["file_offset"], record["original_bytes"])
    if record["category"] == "function_map_table" and record.get("original_raw_bytes"):
        compare("$.original_raw_bytes", record["file_offset"], record["original_raw_bytes"])
    tables: list[tuple[str, list[dict[str, Any]]]] = []
    if record["category"] == "bosch_dtc":
        tables = [("$.mask_table", record["mask_table"]), ("$.error_path_table", record["error_path_table"])]
    elif record["category"] == "non_bosch_dtc":
        tables = [("$.tables", record["tables"])]
    for base, entries in tables:
        for i, e in enumerate(entries):
            compare(f"{base}[{i}].original_bytes", e["entry_file_offset"], e["original_bytes"])
    return issues
