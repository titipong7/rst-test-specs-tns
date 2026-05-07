from __future__ import annotations

from typing import Any

import pytest

from rst_compliance.rdap_conformance import (
    RdapConformanceClient,
    RdapConformanceConfig,
    RdapConformanceError,
    validate_rdap_payload,
)


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.last_call: dict[str, Any] = {}

    def get(self, url: str, headers: dict[str, str], timeout: int) -> _FakeResponse:
        self.last_call = {"url": url, "headers": headers, "timeout": timeout}
        return _FakeResponse(self.payload)


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
    assert session.last_call["url"] == "https://rdap.example.test"
    assert "application/rdap+json" in session.last_call["headers"]["Accept"]


def test_validate_rdap_payload_requires_mandatory_fields(base_rdap_payload: dict[str, Any]) -> None:
    payload = dict(base_rdap_payload)
    payload.pop("notices")

    with pytest.raises(RdapConformanceError, match="missing mandatory field: notices"):
        validate_rdap_payload(payload=payload, registry_data_model="maximum")


def test_validate_rdap_payload_requires_vcardarray_in_entities(base_rdap_payload: dict[str, Any]) -> None:
    payload = dict(base_rdap_payload)
    payload["entities"] = [{"roles": ["registrant"]}]

    with pytest.raises(RdapConformanceError, match="vcardArray"):
        validate_rdap_payload(payload=payload, registry_data_model="maximum")


def test_validate_rdap_payload_requires_registrant_for_maximum(base_rdap_payload: dict[str, Any]) -> None:
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
    payload = dict(base_rdap_payload)
    payload["entities"] = [
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
        }
    ]

    validate_rdap_payload(payload=payload, registry_data_model=data_model)


def test_validate_rdap_payload_rejects_unknown_registry_data_model(base_rdap_payload: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="general.registryDataModel"):
        validate_rdap_payload(payload=base_rdap_payload, registry_data_model="unsupported")
