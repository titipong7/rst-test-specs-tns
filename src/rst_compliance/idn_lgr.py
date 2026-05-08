"""IDN label validation using Label Generation Rules (LGR).

Validates Internationalized Domain Name (IDN) labels against LGR policies
for .th / .ไทย TLDs, aligned with ICANN RST v2.0 requirements.

Implements:
  - Unicode category checks (letters, digits, hyphens)
  - Whole-label evaluation rules (leading/trailing hyphen, double hyphen at 3-4)
  - Script homogeneity check (all code points must belong to the same script)
  - Thai-script specific character set validation
  - IDNA2008 ACE prefix (xn--) detection
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass


# Thai Unicode block: U+0E00–U+0E7F
_THAI_BLOCK_START = 0x0E00
_THAI_BLOCK_END = 0x0E7F

# Allowed ASCII code points in a label (digits + hyphen for mixed labels)
_ASCII_DIGITS = set("0123456789")
_HYPHEN = "-"

# Script names assigned by Unicode (simplified subset used here)
_SCRIPT_LATIN = "Latin"
_SCRIPT_THAI = "Thai"
_SCRIPT_COMMON = "Common"


class LgrValidationError(ValueError):
    """Raised when a label fails LGR / IDN validation."""

    def __init__(self, label: str, reason: str, rst_code: str | None = None) -> None:
        self.label = label
        self.reason = reason
        self.rst_code = rst_code
        super().__init__(f"[{rst_code or 'IDN_ERROR'}] Label {label!r}: {reason}")


@dataclass(frozen=True)
class LgrValidationResult:
    label: str
    is_valid: bool
    reason: str
    rst_code: str | None = None
    script: str | None = None


def _unicode_script(cp: str) -> str:
    """Return a simplified script name for a Unicode code point.

    This uses the Unicode name heuristic rather than the full Script property
    database (which requires the `regex` library).  For production use the
    `regex` library with Unicode script support should be preferred.

    ASCII digits (U+0030–U+0039) and hyphens are treated as ``Common`` because
    they are script-neutral and are permitted in IDN labels alongside any script.
    """
    code = ord(cp)

    # ASCII digits and hyphen are script-neutral (Common)
    if cp in _ASCII_DIGITS or cp == _HYPHEN:
        return _SCRIPT_COMMON

    if _THAI_BLOCK_START <= code <= _THAI_BLOCK_END:
        return _SCRIPT_THAI
    cat = unicodedata.category(cp)
    if cat.startswith("L") or cat.startswith("N"):
        try:
            name = unicodedata.name(cp, "")
        except ValueError:
            return "Unknown"
        if name.startswith("LATIN"):
            return _SCRIPT_LATIN
        if name.startswith("THAI"):
            return _SCRIPT_THAI
        return "Other"
    return _SCRIPT_COMMON


def _is_thai_codepoint(cp: str) -> bool:
    return _THAI_BLOCK_START <= ord(cp) <= _THAI_BLOCK_END


def validate_idn_label(label: str, *, tld: str = "") -> LgrValidationResult:
    """Validate a single IDN label against LGR rules for .th / .ไทย.

    Args:
        label: The ACE-decoded Unicode label string (not the xn-- form).
        tld:   The TLD context (used for Thai-specific checks when applicable).

    Returns:
        A :class:`LgrValidationResult` indicating pass or fail.
    """
    if not label:
        return LgrValidationResult(
            label=label, is_valid=False, reason="Empty label", rst_code="IDN_EMPTY_LABEL"
        )

    if label.startswith("xn--"):
        return LgrValidationResult(
            label=label,
            is_valid=False,
            reason="Label must be supplied in Unicode form (not ACE/xn-- prefix)",
            rst_code="IDN_ACE_PREFIX_NOT_ALLOWED",
        )

    if label.startswith(_HYPHEN) or label.endswith(_HYPHEN):
        return LgrValidationResult(
            label=label,
            is_valid=False,
            reason="Label must not start or end with a hyphen (IDNA2008 §5.4)",
            rst_code="IDN_LEADING_TRAILING_HYPHEN",
        )

    if len(label) >= 4 and label[2:4] == "--":
        return LgrValidationResult(
            label=label,
            is_valid=False,
            reason="Label must not contain '--' in the third and fourth positions (IDNA2008 §5.4)",
            rst_code="IDN_DOUBLE_HYPHEN_3_4",
        )

    scripts: set[str] = set()
    for cp in label:
        script = _unicode_script(cp)
        if script not in (_SCRIPT_COMMON,):
            scripts.add(script)

    real_scripts = scripts - {_SCRIPT_COMMON}
    detected_script = next(iter(real_scripts)) if real_scripts else _SCRIPT_COMMON

    is_thai_tld = tld.lower() in {"th", "ไทย", ".th", ".ไทย"}
    if is_thai_tld:
        for cp in label:
            if not _is_thai_codepoint(cp) and cp not in _ASCII_DIGITS and cp != _HYPHEN:
                return LgrValidationResult(
                    label=label,
                    is_valid=False,
                    reason=(
                        f"Character {cp!r} (U+{ord(cp):04X}) is not in the Thai Unicode block "
                        "(U+0E00–U+0E7F) as required by the .th/.ไทย LGR"
                    ),
                    rst_code="IDN_CHAR_NOT_IN_LGR",
                    script=detected_script,
                )

    if len(real_scripts) > 1:
        return LgrValidationResult(
            label=label,
            is_valid=False,
            reason=f"Label mixes scripts: {sorted(real_scripts)} — labels must be script-homogeneous",
            rst_code="IDN_MIXED_SCRIPT",
        )

    return LgrValidationResult(
        label=label,
        is_valid=True,
        reason="Label passes LGR validation",
        rst_code=None,
        script=detected_script,
    )


def validate_idn_labels(labels: list[str], *, tld: str = "") -> list[LgrValidationResult]:
    """Validate a list of IDN labels and return one result per label."""
    return [validate_idn_label(label, tld=tld) for label in labels]


def validate_idn_domain(domain: str, *, tld: str = "") -> list[LgrValidationResult]:
    """Validate every label in a dot-separated domain name.

    The trailing empty label (from a trailing dot) is ignored.
    """
    parts = domain.rstrip(".").split(".")
    return validate_idn_labels(parts, tld=tld)
