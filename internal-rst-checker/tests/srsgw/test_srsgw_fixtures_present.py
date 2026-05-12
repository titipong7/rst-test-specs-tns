"""Smoke checks ensuring the SRSGW suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-SRSGW
    inc/srsgw/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "srsgw"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "srsgw-01": {
        "happy": ["01-connectivity/hello.xml"],
        "negative": [],
    },
    "srsgw-02": {
        "happy": ["02-host-create/gateway-create.xml", "02-host-create/primary-info.success.xml"],
        "negative": ["02-host-create/primary-info.failure.xml"],
    },
    "srsgw-03": {
        "happy": ["03-contact-create/gateway-create.xml", "03-contact-create/primary-info.success.xml"],
        "negative": ["03-contact-create/primary-info.failure.xml"],
    },
    "srsgw-04": {
        "happy": ["04-domain-create/gateway-create.xml", "04-domain-create/primary-info.success.xml"],
        "negative": ["04-domain-create/primary-info.failure.xml"],
    },
    "srsgw-05": {
        "happy": ["05-domain-renew/gateway-renew.xml", "05-domain-renew/primary-info.success.xml"],
        "negative": ["05-domain-renew/primary-info.failure.xml"],
    },
    "srsgw-06": {
        "happy": [
            "06-domain-transfer/gateway-request.xml",
            "06-domain-transfer/gateway-approve.xml",
            "06-domain-transfer/primary-info.success.xml",
        ],
        "negative": ["06-domain-transfer/primary-info.failure.xml"],
    },
    "srsgw-08": {
        "happy": ["08-domain-delete/gateway-delete.xml", "08-domain-delete/primary-info.success.xml"],
        "negative": ["08-domain-delete/primary-info.failure.xml"],
    },
    "srsgw-09": {
        "happy": ["09-host-update/gateway-update.xml", "09-host-update/primary-info.success.xml"],
        "negative": ["09-host-update/primary-info.failure.xml"],
    },
    "srsgw-10": {
        "happy": ["10-host-delete/gateway-delete.xml", "10-host-delete/primary-info.success.xml"],
        "negative": ["10-host-delete/primary-info.failure.xml"],
    },
    "srsgw-11": {
        "happy": ["11-contact-update/gateway-update.xml", "11-contact-update/primary-info.success.xml"],
        "negative": ["11-contact-update/primary-info.failure.xml"],
    },
    "srsgw-12": {
        "happy": ["12-contact-delete/gateway-delete.xml", "12-contact-delete/primary-info.success.xml"],
        "negative": ["12-contact-delete/primary-info.failure.xml"],
    },
    "srsgw-13": {
        "happy": ["13-domain-rdap/rdap-primary.success.json", "13-domain-rdap/rdap-gateway.success.json"],
        "negative": ["13-domain-rdap/rdap-gateway.failure.json"],
    },
    "srsgw-14": {
        "happy": ["14-nameserver-rdap/rdap-primary.success.json", "14-nameserver-rdap/rdap-gateway.success.json"],
        "negative": ["14-nameserver-rdap/rdap-gateway.failure.json"],
    },
    "srsgw-15": {
        "happy": ["15-registrar-rdap/rdap-primary.success.json", "15-registrar-rdap/rdap-gateway.success.json"],
        "negative": ["15-registrar-rdap/rdap-gateway.failure.json"],
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


def test_srsgw_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_srsgw_case_has_required_fixtures(case_id: str) -> None:
    """Every active case keeps its happy-path fixture set.

    `srsgw-01` is connectivity-only and has no spec-level negative path
    fixture beyond the happy `<hello/>` frame; the negative cases are
    delegated to the EPP `epp-01` fixture set.
    """

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
def test_srsgw_json_fixtures_parse(path: Path | None) -> None:
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
def test_srsgw_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


def test_srsgw_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        f"Real .env files must never be committed under fixtures/srsgw: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
