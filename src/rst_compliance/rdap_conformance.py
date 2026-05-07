from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import requests


class RegistryDataModel(str, Enum):
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    PER_REGISTRAR = "per-registrar"

    @classmethod
    def parse(cls, value: str | "RegistryDataModel") -> "RegistryDataModel":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(
                "general.registryDataModel must be one of: minimum, maximum, per-registrar"
            ) from exc


class RdapConformanceError(ValueError):
    """Raised when an RDAP payload fails conformance checks."""


@dataclass(frozen=True)
class RdapConformanceConfig:
    base_url: str
    registry_data_model: RegistryDataModel | str
    timeout_seconds: int = 30


class RdapConformanceClient:
    """Minimal RDAP checker aligned to ICANN RDAPCT-style checks for v2026.04."""

    def __init__(self, config: RdapConformanceConfig, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()

    def run_base_url_check(self) -> dict[str, Any]:
        endpoint = self.config.base_url.rstrip("/")
        headers = {"Accept": "application/rdap+json, application/json"}
        response = self.session.get(endpoint, headers=headers, timeout=self.config.timeout_seconds)
        response.raise_for_status()

        payload = response.json()
        model = RegistryDataModel.parse(self.config.registry_data_model)
        validate_rdap_payload(payload=payload, registry_data_model=model)
        return payload


def validate_rdap_payload(*, payload: dict[str, Any], registry_data_model: RegistryDataModel | str) -> None:
    model = RegistryDataModel.parse(registry_data_model)

    if not isinstance(payload, dict):
        raise RdapConformanceError("RDAP response must be a JSON object")

    for field in ("rdapConformance", "links", "status", "notices", "entities"):
        if field not in payload:
            raise RdapConformanceError(f"RDAP response missing mandatory field: {field}")

    if not isinstance(payload["rdapConformance"], list) or not payload["rdapConformance"]:
        raise RdapConformanceError("rdapConformance must be a non-empty array")

    if not isinstance(payload["links"], list) or not payload["links"]:
        raise RdapConformanceError("links must be a non-empty array")
    for link in payload["links"]:
        if not isinstance(link, dict) or not link.get("href") or not link.get("rel"):
            raise RdapConformanceError("each link must include rel and href")

    if not isinstance(payload["status"], list) or not payload["status"]:
        raise RdapConformanceError("status must be a non-empty array")

    if not isinstance(payload["notices"], list) or not payload["notices"]:
        raise RdapConformanceError("notices must be a non-empty array")

    entities = payload["entities"]
    if not isinstance(entities, list) or not entities:
        raise RdapConformanceError("entities must be a non-empty array")

    for entity in entities:
        if not isinstance(entity, dict):
            raise RdapConformanceError("each entity must be an object")
        vcard_array = entity.get("vcardArray")
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            raise RdapConformanceError("each entity must include vcardArray")
        if vcard_array[0] != "vcard":
            raise RdapConformanceError("entity vcardArray must start with 'vcard'")

    if model is RegistryDataModel.MAXIMUM and not _has_registrant_entity(entities):
        raise RdapConformanceError(
            "maximum registry data model requires at least one registrant entity"
        )


def _has_registrant_entity(entities: list[dict[str, Any]]) -> bool:
    for entity in entities:
        roles = entity.get("roles", [])
        if isinstance(roles, list) and "registrant" in roles:
            return True
    return False
