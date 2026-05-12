"""Smoke checks ensuring the IDN suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-IDN
    inc/idn/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "idn"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "idn-01": {
        "happy": ["01-label-validation/create.success.xml"],
        "negative": [
            "01-label-validation/create.failure.xml",
            "01-label-validation/variant-create.failure.xml",
        ],
    },
    "idn-02": {
        # Spec only describes a reject path: "the EPP server MUST reject
        # the command". The happy outcome is "test is skipped" when no TLD
        # has idnOnly=true. We therefore only ship a negative fixture.
        "happy": [],
        "negative": ["02-ascii-in-idn-only-tld/create.failure.xml"],
    },
}


def _all_fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURE_DIR.rglob("*") if p.is_file() and p.name != "README.md")


def _files_by_suffix(suffix: str) -> list[Path]:
    return [p for p in _all_fixture_files() if p.suffix == suffix]


def _ids_or_placeholder(items: list[Path], placeholder: str) -> list[str]:
    if not items:
        return [placeholder]
    return [str(p.relative_to(FIXTURE_DIR)) for p in items]


_JSON_FILES = _files_by_suffix(".json")
_XML_FILES = _files_by_suffix(".xml")


def test_idn_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_idn_case_has_required_fixtures(case_id: str) -> None:
    for kind in ("happy", "negative"):
        for relpath in ACTIVE_CASES[case_id][kind]:
            target = FIXTURE_DIR / relpath
            assert target.is_file(), (
                f"{case_id}: missing {kind} fixture {target.relative_to(FIXTURE_DIR.parent)}."
            )


@pytest.mark.parametrize(
    "path",
    _JSON_FILES or [None],
    ids=_ids_or_placeholder(_JSON_FILES, "no-json-fixtures"),
)
def test_idn_json_fixtures_parse(path: Path | None) -> None:
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
def test_idn_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_idn_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        f"Real .env files must never be committed under fixtures/idn: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
