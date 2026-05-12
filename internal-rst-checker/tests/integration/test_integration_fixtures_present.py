"""Smoke checks ensuring the Integration suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-Integration
    inc/integration/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "integration"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "integration-01": {
        "happy": ["01-epp-rdap/epp-create.xml", "01-epp-rdap/rdap-response.success.json"],
        "negative": ["01-epp-rdap/rdap-response.failure.json"],
    },
    "integration-02": {
        "happy": ["02-epp-dns/epp-create.xml", "02-epp-dns/dns-query.success.json"],
        "negative": ["02-epp-dns/dns-query.failure.json"],
    },
    "integration-03": {
        "happy": ["03-epp-rde/epp-create.xml", "03-epp-rde/rde-deposit.success.xml"],
        "negative": ["03-epp-rde/rde-deposit.failure.xml"],
    },
    "integration-04": {
        "happy": [
            "04-glue-policy-host-objects/epp-create-domain.xml",
            "04-glue-policy-host-objects/epp-create-host.xml",
            "04-glue-policy-host-objects/epp-update-domain.xml",
            "04-glue-policy-host-objects/dns-query.success.json",
        ],
        "negative": ["04-glue-policy-host-objects/dns-query.failure.json"],
    },
    "integration-05": {
        "happy": [
            "05-glue-policy-host-attributes/epp-create-domain-1.xml",
            "05-glue-policy-host-attributes/epp-create-domain-2.xml",
            "05-glue-policy-host-attributes/dns-query.success.json",
        ],
        "negative": ["05-glue-policy-host-attributes/dns-query.failure.json"],
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


def test_integration_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_integration_case_has_required_fixtures(case_id: str) -> None:
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
def test_integration_json_fixtures_parse(path: Path | None) -> None:
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
def test_integration_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_integration_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        f"Real .env files must never be committed under fixtures/integration: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
