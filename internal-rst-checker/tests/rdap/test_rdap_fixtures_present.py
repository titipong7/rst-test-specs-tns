"""Smoke checks ensuring the RDAP suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-RDAP
    inc/rdap/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "rdap"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "rdap-01": {
        "happy": ["01-domain-query/response.success.json"],
        "negative": ["01-domain-query/response.failure.json"],
    },
    "rdap-02": {
        "happy": ["02-nameserver-query/response.success.json"],
        "negative": ["02-nameserver-query/response.failure.json"],
    },
    "rdap-03": {
        "happy": ["03-entity-query/response.success.json"],
        "negative": ["03-entity-query/response.failure.json"],
    },
    "rdap-04": {
        "happy": ["04-help-query/response.success.json"],
        "negative": ["04-help-query/response.failure.json"],
    },
    "rdap-05": {
        "happy": ["05-domain-head/response.success.txt"],
        "negative": ["05-domain-head/response.failure.txt"],
    },
    "rdap-06": {
        "happy": ["06-nameserver-head/response.success.txt"],
        "negative": ["06-nameserver-head/response.failure.txt"],
    },
    "rdap-07": {
        "happy": ["07-entity-head/response.success.txt"],
        "negative": ["07-entity-head/response.failure.txt"],
    },
    "rdap-08": {
        "happy": ["08-non-existent-domain/response.success.json"],
        "negative": ["08-non-existent-domain/response.failure.json"],
    },
    "rdap-09": {
        "happy": ["09-non-existent-nameserver/response.success.json"],
        "negative": ["09-non-existent-nameserver/response.failure.json"],
    },
    "rdap-10": {
        "happy": ["10-non-existent-entity/response.success.json"],
        "negative": ["10-non-existent-entity/response.failure.json"],
    },
    "rdap-91": {
        "happy": ["91-tls-conformance/probe.success.json"],
        "negative": ["91-tls-conformance/probe.failure.json"],
    },
    "rdap-92": {
        "happy": ["92-service-port-consistency/probe.success.json"],
        "negative": ["92-service-port-consistency/probe.failure.json"],
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


def test_rdap_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_rdap_case_has_happy_and_negative_fixtures(case_id: str) -> None:
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
def test_rdap_json_fixtures_parse(path: Path | None) -> None:
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
def test_rdap_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_rdap_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        f"Real .env files must never be committed under fixtures/rdap: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
