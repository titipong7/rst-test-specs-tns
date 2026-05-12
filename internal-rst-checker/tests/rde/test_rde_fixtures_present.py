"""Smoke checks ensuring the RDE suite fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-RDE
    inc/rde/cases.yaml
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "rde"

ACTIVE_CASES: dict[str, dict[str, list[str]]] = {
    "rde-01": {
        "happy": ["01-deposit-filename/filename.success.txt"],
        "negative": ["01-deposit-filename/filename.failure.txt"],
    },
    "rde-02": {
        "happy": ["02-signature/signature.success.sig.example"],
        "negative": ["02-signature/signature.failure.sig.example"],
    },
    "rde-03": {
        "happy": ["03-decrypt/deposit.success.ryde.example"],
        "negative": ["03-decrypt/deposit.failure.ryde.example"],
    },
    "rde-04": {
        "happy": ["04-xml-csv/deposit.success.xml", "04-xml-csv/deposit.success.csv"],
        "negative": ["04-xml-csv/deposit.failure.xml", "04-xml-csv/deposit.failure.csv"],
    },
    "rde-05": {
        "happy": ["05-object-types/header.success.xml"],
        "negative": ["05-object-types/header.failure.xml"],
    },
    "rde-06": {
        "happy": ["06-object-counts/header.success.xml"],
        "negative": ["06-object-counts/header.failure.xml"],
    },
    "rde-07": {
        "happy": ["07-domain/domain.success.xml"],
        "negative": ["07-domain/domain.failure.xml"],
    },
    "rde-08": {
        "happy": ["08-host/host.success.xml"],
        "negative": ["08-host/host.failure.xml"],
    },
    "rde-09": {
        "happy": ["09-contact/contact.success.xml"],
        "negative": ["09-contact/contact.failure.xml"],
    },
    "rde-10": {
        "happy": ["10-registrar/registrar.success.xml"],
        "negative": ["10-registrar/registrar.failure.xml"],
    },
    "rde-11": {
        "happy": ["11-idn-table/idn.success.xml"],
        "negative": ["11-idn-table/idn.failure.xml"],
    },
    "rde-12": {
        "happy": ["12-nndn/nndn.success.xml"],
        "negative": ["12-nndn/nndn.failure.xml"],
    },
    "rde-13": {
        "happy": ["13-epp-params/epp-params.success.xml"],
        "negative": ["13-epp-params/epp-params.failure.xml"],
    },
    "rde-14": {
        "happy": ["14-policy/policy.success.xml"],
        "negative": ["14-policy/policy.failure.xml"],
    },
}

WELL_FORMED_XML_PATHS: tuple[str, ...] = (
    "04-xml-csv/deposit.success.xml",
    "05-object-types/header.success.xml",
    "06-object-counts/header.success.xml",
    "07-domain/domain.success.xml",
    "08-host/host.success.xml",
    "09-contact/contact.success.xml",
    "10-registrar/registrar.success.xml",
    "11-idn-table/idn.success.xml",
    "12-nndn/nndn.success.xml",
    "13-epp-params/epp-params.success.xml",
    "14-policy/policy.success.xml",
    "04-xml-csv/deposit.failure.xml",
    "05-object-types/header.failure.xml",
    "06-object-counts/header.failure.xml",
    "07-domain/domain.failure.xml",
    "08-host/host.failure.xml",
    "09-contact/contact.failure.xml",
    "10-registrar/registrar.failure.xml",
    "11-idn-table/idn.failure.xml",
    "12-nndn/nndn.failure.xml",
    "13-epp-params/epp-params.failure.xml",
    "14-policy/policy.failure.xml",
)


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


def test_rde_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), f"Missing fixtures folder: {FIXTURE_DIR}."


@pytest.mark.parametrize("case_id", sorted(ACTIVE_CASES))
def test_every_active_rde_case_has_happy_and_negative_fixtures(case_id: str) -> None:
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
def test_rde_json_fixtures_parse(path: Path | None) -> None:
    if path is None:
        pytest.skip("No JSON fixtures present in this suite.")
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        pytest.fail(f"Fixture {path.name} is not valid JSON: {exc}")


@pytest.mark.parametrize("relpath", WELL_FORMED_XML_PATHS)
def test_rde_xml_fixtures_are_well_formed(relpath: str) -> None:
    """RDE XML fixtures, both happy and negative, MUST parse as XML.

    Negative-path fixtures intentionally violate higher-level RDE rules
    (invalid roid, wrong country code, etc.) but still need to be valid
    XML so that downstream rule-driven assessors can locate the elements
    that should be flagged.
    """

    path = FIXTURE_DIR / relpath
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {relpath} is not well-formed XML: {exc}")


def test_rde_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        f"Real .env files must never be committed under fixtures/rde: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
