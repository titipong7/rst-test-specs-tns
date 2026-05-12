"""Smoke checks ensuring the DNSSEC-Ops suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-DNSSEC-Ops
    inc/dnssec-ops/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "dnssec-ops"

# All three cases are spec'd as `Implemented: false` in cases.yaml, but
# fixtures are kept for matrix continuity (same pattern as rde-12).
ACTIVE_CASES: tuple[str, ...] = ("01", "02", "03")

CASE_LABELS: dict[str, str] = {
    "01": "dnssecOps01-ZSKRollover",
    "02": "dnssecOps02-KSKRollover",
    "03": "dnssecOps03-AlgorithmRollover",
}


def _all_fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURE_DIR.iterdir() if p.is_file() and p.name != "README.md")


def _files_by_suffix(suffix: str) -> list[Path]:
    return [p for p in _all_fixture_files() if p.suffix == suffix]


def _ids_or_placeholder(items: list[Path], placeholder: str) -> list[str]:
    if not items:
        return [placeholder]
    return [str(p.relative_to(FIXTURE_DIR)) for p in items]


_JSON_FILES = _files_by_suffix(".json")
_XML_FILES = _files_by_suffix(".xml")


def test_dnssec_ops_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_nn", ACTIVE_CASES)
def test_every_active_dnssec_ops_case_has_at_least_one_fixture(case_nn: str) -> None:
    matches = sorted(FIXTURE_DIR.glob(f"{case_nn}-*"))
    assert matches, (
        f"DNSSEC-Ops case prefix '{case_nn}-' ({CASE_LABELS[case_nn]}) "
        f"has no fixtures under {FIXTURE_DIR}."
    )


@pytest.mark.parametrize(
    "path",
    _JSON_FILES or [None],
    ids=_ids_or_placeholder(_JSON_FILES, "no-json-fixtures"),
)
def test_dnssec_ops_json_fixtures_parse(path: Path | None) -> None:
    if path is None:
        pytest.skip("No JSON fixtures present in this suite.")
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        pytest.fail(f"Fixture {path.name} is not valid JSON: {exc}")


@pytest.mark.parametrize(
    "path",
    _XML_FILES or [None],
    ids=_ids_or_placeholder(_XML_FILES, "no-xml-fixtures"),
)
def test_dnssec_ops_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_dnssec_ops_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        "Real .env files must never be committed under fixtures/dnssec-ops: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
