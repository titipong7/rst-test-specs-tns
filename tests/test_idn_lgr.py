"""Tests for the IDN/LGR label validation module (idn_lgr.py).

Covers RST test case: IDN label validation for .th / .ไทย TLDs as per
ICANN RST v2.0 and IDNA2008 (RFC 5891).
"""
from __future__ import annotations

import pytest

from rst_compliance.idn_lgr import (
    LgrValidationResult,
    validate_idn_domain,
    validate_idn_label,
    validate_idn_labels,
)


# ---------------------------------------------------------------------------
# Single-label validation
# ---------------------------------------------------------------------------


def test_ascii_latin_label_passes_without_tld_context() -> None:
    result = validate_idn_label("example")
    assert result.is_valid is True


def test_empty_label_fails() -> None:
    result = validate_idn_label("")
    assert result.is_valid is False
    assert result.rst_code == "IDN_EMPTY_LABEL"


def test_ace_prefixed_label_fails() -> None:
    result = validate_idn_label("xn--nxasmq6b")
    assert result.is_valid is False
    assert result.rst_code == "IDN_ACE_PREFIX_NOT_ALLOWED"


def test_leading_hyphen_fails() -> None:
    result = validate_idn_label("-example")
    assert result.is_valid is False
    assert result.rst_code == "IDN_LEADING_TRAILING_HYPHEN"


def test_trailing_hyphen_fails() -> None:
    result = validate_idn_label("example-")
    assert result.is_valid is False
    assert result.rst_code == "IDN_LEADING_TRAILING_HYPHEN"


def test_double_hyphen_at_position_3_4_fails() -> None:
    result = validate_idn_label("ab--example")
    assert result.is_valid is False
    assert result.rst_code == "IDN_DOUBLE_HYPHEN_3_4"


def test_internal_single_hyphen_passes() -> None:
    result = validate_idn_label("my-label")
    assert result.is_valid is True


def test_mixed_script_fails() -> None:
    result = validate_idn_label("aเ")
    assert result.is_valid is False
    assert result.rst_code == "IDN_MIXED_SCRIPT"


# ---------------------------------------------------------------------------
# Thai-specific TLD validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tld", ["th", "ไทย", ".th", ".ไทย"])
def test_thai_label_passes_for_thai_tld(tld: str) -> None:
    thai_label = "สวัสดี"
    result = validate_idn_label(thai_label, tld=tld)
    assert result.is_valid is True


def test_thai_tld_rejects_non_thai_non_digit_chars() -> None:
    result = validate_idn_label("สวัสดีa", tld="th")
    assert result.is_valid is False
    assert result.rst_code == "IDN_CHAR_NOT_IN_LGR"


def test_thai_tld_allows_digits_mixed_with_thai() -> None:
    result = validate_idn_label("ไทย2", tld="th")
    assert result.is_valid is True


def test_non_thai_tld_does_not_apply_thai_block_restriction() -> None:
    result = validate_idn_label("example", tld="com")
    assert result.is_valid is True


# ---------------------------------------------------------------------------
# Batch and domain-level validation
# ---------------------------------------------------------------------------


def test_validate_idn_labels_returns_one_result_per_label() -> None:
    results = validate_idn_labels(["example", "", "xn--nxasmq6b"])
    assert len(results) == 3
    assert results[0].is_valid is True
    assert results[1].is_valid is False
    assert results[2].is_valid is False


def test_validate_idn_domain_splits_on_dots() -> None:
    results = validate_idn_domain("สวัสดี.ไทย", tld="th")
    assert all(isinstance(r, LgrValidationResult) for r in results)
    assert len(results) == 2


def test_validate_idn_domain_ignores_trailing_dot() -> None:
    results = validate_idn_domain("example.th.", tld="th")
    assert len(results) == 2


def test_validate_idn_domain_all_pass_for_clean_input() -> None:
    results = validate_idn_domain("สวัสดี.ไทย", tld="th")
    assert all(r.is_valid for r in results)
