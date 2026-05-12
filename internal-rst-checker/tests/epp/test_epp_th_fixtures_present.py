"""Smoke checks ensuring the EPP `.th` fixture set stays complete and well-formed.

Spec reference:
    https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html#Test-Suite-EPP
    inc/epp/cases.yaml

This file is the canonical template that every per-suite
``test_<suite>_fixtures_present.py`` guard mirrors. The contract:

- ``FIXTURE_DIR`` points at the suite's fixture folder (flat layout).
- ``ACTIVE_CASES`` carries the real spec ``case_id`` strings; the
  on-disk 2-digit prefix is resolved through ``CASE_PREFIX``.
- The five ``test_*`` functions cover presence + ``.xml``, ``.json``,
  ``.csv``, and PGP-armored ``.asc`` / ``.gpg`` payloads, plus an
  env-leak guard.
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "epp" / "th"

ACTIVE_CASES: tuple[str, ...] = (
    "epp-01", "epp-03", "epp-04", "epp-14", "epp-16",
    "epp-18", "epp-19", "epp-20", "epp-21",
    "epp-26", "epp-27",
)

CASE_PREFIX: dict[str, str] = {
    "epp-01": "01",
    "epp-03": "03",
    "epp-04": "04",
    "epp-14": "14",
    "epp-16": "16",
    "epp-18": "18",
    "epp-19": "19",
    "epp-20": "20",
    "epp-21": "21",
    "epp-26": "26",
    "epp-27": "27",
}


def _all_fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURE_DIR.iterdir() if p.is_file() and p.name != "README.md")


def _files_by_suffix(suffix: str) -> list[Path]:
    return [p for p in _all_fixture_files() if p.suffix == suffix]


def _files_by_suffixes(*suffixes: str) -> list[Path]:
    allowed = set(suffixes)
    return [p for p in _all_fixture_files() if p.suffix in allowed]


def _ids_or_placeholder(items: list[Path], placeholder: str) -> list[str]:
    if not items:
        return [placeholder]
    return [str(p.relative_to(FIXTURE_DIR)) for p in items]


_JSON_FILES = _files_by_suffix(".json")
_XML_FILES = _files_by_suffix(".xml")
_CSV_FILES = _files_by_suffix(".csv")
_PGP_FILES = _files_by_suffixes(".asc", ".gpg")


def test_epp_th_fixture_directory_exists() -> None:
    assert FIXTURE_DIR.is_dir(), (
        f"Missing fixtures folder: {FIXTURE_DIR}. "
        "Restore from git history or rerun the bootstrap."
    )


@pytest.mark.parametrize("case_id", ACTIVE_CASES)
def test_every_active_epp_case_has_at_least_one_fixture(case_id: str) -> None:
    nn = CASE_PREFIX[case_id]
    matches = sorted(FIXTURE_DIR.glob(f"{nn}-*"))
    assert matches, (
        f"{case_id}: no fixture matching '{nn}-*' under {FIXTURE_DIR}."
    )


@pytest.mark.parametrize(
    "path",
    _JSON_FILES or [None],
    ids=_ids_or_placeholder(_JSON_FILES, "no-json-fixtures"),
)
def test_epp_json_fixtures_parse(path: Path | None) -> None:
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
def test_epp_xml_fixtures_are_well_formed(path: Path | None) -> None:
    if path is None:
        pytest.skip("No XML fixtures present in this suite.")
    try:
        ET.fromstring(path.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        pytest.fail(f"Fixture {path.name} is not well-formed XML: {exc}")


@pytest.mark.parametrize(
    "path",
    _CSV_FILES or [None],
    ids=_ids_or_placeholder(_CSV_FILES, "no-csv-fixtures"),
)
def test_epp_csv_fixtures_parse(path: Path | None) -> None:
    if path is None:
        pytest.skip("No CSV fixtures present in this suite.")
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            for _ in csv.reader(fh):
                continue
    except csv.Error as exc:
        pytest.fail(f"Fixture {path.name} is not valid CSV: {exc}")


@pytest.mark.parametrize(
    "path",
    _PGP_FILES or [None],
    ids=_ids_or_placeholder(_PGP_FILES, "no-pgp-fixtures"),
)
def test_epp_pgp_armored_headers_present(path: Path | None) -> None:
    if path is None:
        pytest.skip("No .asc/.gpg fixtures present in this suite.")
    body = path.read_bytes()
    assert len(body) > 0, f"Fixture {path.name} is empty (0 bytes)."
    assert b"-----BEGIN PGP" in body, (
        f"Fixture {path.name} is missing the '-----BEGIN PGP' armor header."
    )


def test_epp_th_no_real_env_files_are_committed() -> None:
    real_envs = [p for p in FIXTURE_DIR.rglob("*.env") if not p.name.endswith(".env.example")]
    assert not real_envs, (
        "Real .env files must never be committed under fixtures/epp/th: "
        f"{[str(p.relative_to(FIXTURE_DIR.parent)) for p in real_envs]}"
    )
