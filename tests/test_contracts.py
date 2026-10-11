import json
from pathlib import Path

import pytest

from core.hexbytes import from_hex, normalize, to_hex
from core.validators import ContractValidator, check_against_bin

ROOT = Path(__file__).resolve().parents[1]
VALID = sorted((ROOT / "schemas" / "examples" / "valid").glob("*.json"))
INVALID = sorted((ROOT / "schemas" / "examples" / "invalid").glob("*.json"))
BIN = (ROOT / "fixtures" / "synthetic" / "synthetic_ecu.bin").read_bytes()


@pytest.fixture(scope="module")
def validator():
    return ContractValidator(ROOT / "schemas")


def _all_issues(validator, record):
    issues = validator.validate(record)
    if not any(i.severity == "error" for i in issues):
        issues += check_against_bin(record, BIN)
    return issues


def test_every_category_has_a_valid_example():
    assert {p.stem for p in VALID} == {"function_on_off", "function_map_table", "bosch_dtc", "non_bosch_dtc"}


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_valid_examples_pass_schema_and_binary_checks(validator, path):
    issues = _all_issues(validator, json.loads(path.read_text()))
    assert [i for i in issues if i.severity == "error"] == []


@pytest.mark.parametrize("path", INVALID, ids=lambda p: p.stem)
def test_invalid_examples_fail_with_expected_code(validator, path):
    record = json.loads(path.read_text())
    expected = record.pop("x_expected_error")
    codes = [i.code for i in _all_issues(validator, record) if i.severity == "error"]
    assert expected in codes


@pytest.mark.parametrize("path", VALID, ids=lambda p: p.stem)
def test_json_round_trip_is_lossless(path):
    text = path.read_text()
    assert json.loads(json.dumps(json.loads(text), ensure_ascii=False)) == json.loads(text)


def test_hex_helpers():
    assert to_hex(b"\x00\xaa\x1f") == "00 AA 1F"
    assert from_hex("00 aa 1F") == b"\x00\xaa\x1f"
    assert normalize("0x00,0xAA 1f") == "00 AA 1F"
    with pytest.raises(ValueError):
        from_hex("00aa")
