"""Smoke checks ensuring the DNS suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-DNS
    inc/dns/cases.yaml

Fixtures live under ``internal-rst-checker/fixtures/dns/`` and feed the DNS
checker's ``dns-zz-idna2008-compliance`` and ``dns-zz-consistency`` flows.
The tests below mirror the EPP guard at
``internal-rst-checker/tests/epp/test_epp_th_fixtures_present.py``.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "dns"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "dns-zz-idna2008-compliance": {
        "happy": ["idna2008-compliance/nameservers.success.json"],
        "negative": ["idna2008-compliance/nameservers.failure.json"],
    },
    "dns-zz-consistency": {
        "happy": ["consistency/nameservers.success.json"],
        "negative": ["consistency/nameservers.failure.json"],
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


def test_dns_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), (
        f"Missing fixtures folder: {FIXTURE_DIR}. "
        "Restore from git history or rerun the bootstrap."
    )


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_dns_case_has_happy_and_negative_fixtures(case_id: str) -> None:
    """Every active case keeps at least one happy + one negative fixture."""
    for kind in ("happy", "negative"):
        for relpath in ACTIVE_CASES[case_id][kind]:
            target = FIXTURE_DIR / relpath
            assert target.is_file(), (
                f"{case_id}: missing {kind} fixture {target.relative_to(FIXTURE_DIR.parent)}. "
                "Add the file or update the manifest."
            )


@pytest.mark.parametrize(
    "path",
    _JSON_FILES or [None],
    ids=_ids_or_placeholder(_JSON_FILES, "no-json-fixtures"),
)
def test_dns_json_fixtures_parse(path: Path | None) -> None:
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
def test_dns_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_dns_no_real_env_files_are_committed() -> None:
    """Only ``*.env.example`` templates may be committed under this suite."""
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        "Real .env files must never be committed under fixtures/dns: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
