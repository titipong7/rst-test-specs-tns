from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError
from xmlschema.validators.exceptions import XMLSchemaValidationError

from rst_compliance.schema_validation import validate_json_payload, validate_xml_payload


def test_json_testcaselog_schema_validation(schema_dirs: tuple[Path, Path]) -> None:
    json_dir, _ = schema_dirs
    validate_json_payload(
        schema_file=json_dir / "testCaseLog.schema.json",
        payload={
            "testCaseId": "dns-01",
            "service": "DNS",
            "status": "passed",
            "startedAt": "2026-04-01T00:00:00Z",
            "finishedAt": "2026-04-01T00:00:05Z",
            "details": {"summary": "ok"},
        },
    )


def test_json_testcaselog_schema_validation_fails_on_missing_fields(schema_dirs: tuple[Path, Path]) -> None:
    json_dir, _ = schema_dirs
    with pytest.raises(ValidationError):
        validate_json_payload(schema_file=json_dir / "testCaseLog.schema.json", payload={"service": "DNS"})


def test_xml_schema_validation_for_epp_payload(schema_dirs: tuple[Path, Path]) -> None:
    _, xml_dir = schema_dirs
    validate_xml_payload(schema_file=xml_dir / "epp-response.xsd", xml_text="<epp>ok</epp>")


def test_xml_schema_validation_rejects_invalid_payload(schema_dirs: tuple[Path, Path]) -> None:
    _, xml_dir = schema_dirs
    with pytest.raises(XMLSchemaValidationError):
        validate_xml_payload(schema_file=xml_dir / "epp-response.xsd", xml_text="<bad>value</bad>")
