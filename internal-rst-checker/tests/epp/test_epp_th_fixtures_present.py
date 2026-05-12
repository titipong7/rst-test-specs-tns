"""Smoke checks ensuring the .th EPP fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-StandardEPP

Fixtures live under ``internal-rst-checker/fixtures/epp/th/`` and are wired
into the StandardEPP smoke suite plus the ``docs/epp-spec-to-test-mapping.md``
table. These tests guard against accidental fixture deletion and malformed XML
so the matrix never silently drifts away from the spec.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "epp" / "th"

ACTIVE_CASES: tuple[str, ...] = (
    "01",
    "02",
    "03",
    "04",
    "05",
    "06",
    "07",
    "08",
    "09",
    "10",
    "11",
    "12",
    "13",
    "14",
    "15",
    "16",
    "17",
    "18",
    "19",
    "20",
    "21",
    "23",
    "24",
    "25",
    "26",
    "27",
)

REMOVED_CASES_WITH_REFERENCE_FIXTURE: tuple[str, ...] = ("22",)


def _xml_fixtures() -> list[Path]:
    return sorted(FIXTURE_DIR.glob("*.xml"))


def test_th_fixture_directory_exists() -> None:
    """Sanity check: the fixtures folder must remain present."""
    assert FIXTURE_DIR.is_dir(), (
        f"Missing fixtures folder: {FIXTURE_DIR}. "
        "Restore from git history or rerun the bootstrap."
    )


@pytest.mark.parametrize("case", ACTIVE_CASES)
def test_every_active_epp_case_has_at_least_one_fixture(case: str) -> None:
    """Every active StandardEPP case must keep at least one fixture file.

    Coverage notes:
        - epp-01..epp-25 use ``<case>-*-success.xml`` / ``<case>-*-failure.xml``.
        - epp-26 / epp-27 use a single fixture re-used for happy + reject
          assertions (wide glue policy / glueless internal host), which is
          why we only require the prefix to exist here.
    """

    matches = sorted(FIXTURE_DIR.glob(f"{case}-*.xml"))
    assert matches, (
        f"epp-{case} has no fixture under {FIXTURE_DIR}. "
        "Add at least one XML fixture so the spec mapping stays complete."
    )


@pytest.mark.parametrize("case", REMOVED_CASES_WITH_REFERENCE_FIXTURE)
def test_removed_case_keeps_reference_fixture(case: str) -> None:
    """Removed cases (e.g. epp-22) keep a labelled reference fixture."""
    matches = sorted(FIXTURE_DIR.glob(f"{case}-*.xml"))
    assert matches, (
        f"epp-{case} is removed in v2026.04 but should keep a reference "
        "fixture for matrix continuity."
    )


@pytest.mark.parametrize("path", _xml_fixtures(), ids=lambda p: p.name)
def test_th_fixtures_are_well_formed_xml(path: Path) -> None:
    """All shipped fixtures must parse as XML (no broken templates)."""
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")
