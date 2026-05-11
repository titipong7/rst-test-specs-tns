from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema.exceptions import ValidationError

from rst_compliance.rdap_conformance import (
    RdapConformanceClient,
    RdapConformanceConfig,
    RdapConformanceError,
    validate_rdap_head_response,
    validate_rdap_response,
    validate_rdap_payload,
)


class _FakeResponse:
    def __init__(
        self,
        payload: dict[str, Any] | None = None,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.last_call: dict[str, Any] = {}
        self.last_head_call: dict[str, Any] = {}

    def get(self, url: str, headers: dict[str, str], timeout: int) -> _FakeResponse:
        self.last_call = {"url": url, "headers": headers, "timeout": timeout}
        return _FakeResponse(self.payload)

    def head(self, url: str, headers: dict[str, str], timeout: int) -> _FakeResponse:
        self.last_head_call = {"url": url, "headers": headers, "timeout": timeout}
        return _FakeResponse(
            status_code=200,
            headers={"access-control-allow-origin": "*"},
            text="",
        )


@pytest.fixture
def base_rdap_payload() -> dict[str, Any]:
    return {
        "rdapConformance": ["rdap_level_0"],
        "links": [
            {
                "value": "https://rdap.example.test/domain/example.tld",
                "rel": "self",
                "href": "https://rdap.example.test/domain/example.tld",
                "type": "application/rdap+json",
            }
        ],
        "status": ["active"],
        "notices": [{"title": "Terms of Service", "description": ["RDAP notice"]}],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
            }
        ],
    }


def test_rdap_base_url_check_calls_base_url_and_validates_payload(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-04 help/base URL conformance and rdap-92 consistency preconditions."""
    session = _FakeSession(payload=base_rdap_payload)
    client = RdapConformanceClient(
        RdapConformanceConfig(
            base_url="https://rdap.example.test/",
            registry_data_model="maximum",
            timeout_seconds=15,
        ),
        session=session,
    )

    response_payload = client.run_base_url_check()

    assert response_payload == base_rdap_payload
    assert client.last_latency_ms is not None
    assert session.last_call["url"] == "https://rdap.example.test"
    assert "application/rdap+json" in session.last_call["headers"]["Accept"]


def test_validate_rdap_response_validates_with_jsonschema(base_rdap_payload: dict[str, Any], tmp_path: Path) -> None:
    """Covers rdap-02, rdap-03, and rdap-04 response-shape validation checks."""
    schema_file = tmp_path / "rdap.schema.json"
    schema_file.write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["rdapConformance", "links", "status", "notices", "entities"],
            }
        ),
        encoding="utf-8",
    )

    validate_rdap_response(
        payload=base_rdap_payload,
        registry_data_model="maximum",
        schema_file=schema_file,
        latency_ms=200,
    )


def test_validate_rdap_response_fails_on_schema_error(base_rdap_payload: dict[str, Any], tmp_path: Path) -> None:
    """Covers rdap-02, rdap-03, and rdap-04 negative schema-validation path."""
    schema_file = tmp_path / "rdap.schema.json"
    schema_file.write_text(json.dumps({"type": "object", "required": ["events"]}), encoding="utf-8")

    with pytest.raises(ValidationError):
        validate_rdap_response(
            payload=base_rdap_payload,
            registry_data_model="maximum",
            schema_file=schema_file,
            latency_ms=200,
        )


def test_validate_rdap_response_fails_when_latency_exceeds_threshold(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-91 latency/security guardrail enforcement."""
    with pytest.raises(RdapConformanceError, match="latency"):
        validate_rdap_response(
            payload=base_rdap_payload,
            registry_data_model="maximum",
            latency_ms=401,
            latency_threshold_ms=400,
        )


def test_validate_rdap_payload_requires_mandatory_fields(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-02, rdap-03, and rdap-04 mandatory payload fields."""
    payload = dict(base_rdap_payload)
    payload.pop("notices")

    with pytest.raises(RdapConformanceError, match="missing mandatory field: notices"):
        validate_rdap_payload(payload=payload, registry_data_model="maximum")


def test_validate_rdap_payload_requires_vcardarray_in_entities(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-03 entity payload requirements for registrar lookups."""
    payload = dict(base_rdap_payload)
    payload["entities"] = [{"roles": ["registrant"]}]

    with pytest.raises(RdapConformanceError, match="vcardArray"):
        validate_rdap_payload(payload=payload, registry_data_model="maximum")


def test_validate_rdap_payload_requires_registrant_for_maximum(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-01 domain query obligations under maximum data model."""
    payload = dict(base_rdap_payload)
    payload["entities"] = [
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
        }
    ]

    with pytest.raises(RdapConformanceError, match="maximum registry data model"):
        validate_rdap_payload(payload=payload, registry_data_model="maximum")


@pytest.mark.parametrize("data_model", ["minimum", "per-registrar"])
def test_validate_rdap_payload_allows_non_registrant_for_minimum_and_per_registrar(
    base_rdap_payload: dict[str, Any], data_model: str
) -> None:
    """Covers rdap-01 behavior for minimum/per-registrar data models."""
    payload = dict(base_rdap_payload)
    payload["entities"] = [
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
        }
    ]

    validate_rdap_payload(payload=payload, registry_data_model=data_model)


def test_validate_rdap_payload_rejects_unknown_registry_data_model(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-01 input validation for general.registryDataModel."""
    with pytest.raises(ValueError, match="general.registryDataModel"):
        validate_rdap_payload(payload=base_rdap_payload, registry_data_model="unsupported")


def test_validate_rdap_head_response_accepts_expected_headers_and_empty_body() -> None:
    """Covers rdap-05, rdap-06, and rdap-07 HEAD success path."""
    response = _FakeResponse(status_code=200, headers={"access-control-allow-origin": "*"}, text="")
    validate_rdap_head_response(response=response)


@pytest.mark.parametrize(
    ("status_code", "headers", "text", "error_match"),
    [
        (404, {"access-control-allow-origin": "*"}, "", "must return 200"),
        (200, {}, "", "access-control-allow-origin"),
        (200, {"access-control-allow-origin": "*"}, "unexpected-body", "must be empty"),
    ],
)
def test_validate_rdap_head_response_rejects_invalid_conditions(
    status_code: int, headers: dict[str, str], text: str, error_match: str
) -> None:
    """Covers rdap-05, rdap-06, and rdap-07 HEAD failure conditions."""
    response = _FakeResponse(status_code=status_code, headers=headers, text=text)
    with pytest.raises(RdapConformanceError, match=error_match):
        validate_rdap_head_response(response=response)


def test_run_head_check_calls_head_endpoint_for_object_path(base_rdap_payload: dict[str, Any]) -> None:
    """Covers rdap-05, rdap-06, and rdap-07 endpoint execution path."""
    session = _FakeSession(payload=base_rdap_payload)
    client = RdapConformanceClient(
        RdapConformanceConfig(
            base_url="https://rdap.example.test/",
            registry_data_model="maximum",
            timeout_seconds=15,
        ),
        session=session,
    )

    client.run_head_check(object_path="/domain/example.tld")

    assert session.last_head_call["url"] == "https://rdap.example.test/domain/example.tld"
