from __future__ import annotations

import copy
import json
import socket
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import urlparse

import requests

from rst_compliance.schema_validation import validate_json_payload


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
    schema_file: Path | None = None
    latency_threshold_ms: int = 400


class RdapConformanceClient:
    """Minimal RDAP checker aligned to ICANN RDAPCT-style checks for v2026.04."""

    def __init__(self, config: RdapConformanceConfig, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()
        self.last_latency_ms: float | None = None

    def run_base_url_check(self) -> dict[str, Any]:
        endpoint = self.config.base_url.rstrip("/")
        headers = {"Accept": "application/rdap+json, application/json"}
        start = perf_counter()
        response = self.session.get(endpoint, headers=headers, timeout=self.config.timeout_seconds)
        self.last_latency_ms = (perf_counter() - start) * 1000
        response.raise_for_status()

        payload = response.json()
        validate_rdap_response(
            payload=payload,
            registry_data_model=self.config.registry_data_model,
            schema_file=self.config.schema_file,
            latency_ms=self.last_latency_ms,
            latency_threshold_ms=self.config.latency_threshold_ms,
        )
        return payload


def validate_rdap_response(
    *,
    payload: dict[str, Any],
    registry_data_model: RegistryDataModel | str,
    latency_ms: float,
    schema_file: Path | None = None,
    latency_threshold_ms: int = 400,
) -> None:
    if schema_file is not None:
        validate_json_payload(schema_file=schema_file, payload=payload)

    validate_rdap_payload(payload=payload, registry_data_model=registry_data_model)

    if latency_ms > latency_threshold_ms:
        raise RdapConformanceError(
            f"RDAP latency {latency_ms:.2f}ms exceeds threshold {latency_threshold_ms}ms"
        )


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

    if model == RegistryDataModel.MAXIMUM and not _has_registrant_entity(entities):
        raise RdapConformanceError(
            "maximum registry data model requires at least one registrant entity"
        )


def _has_registrant_entity(entities: list[dict[str, Any]]) -> bool:
    for entity in entities:
        roles = entity.get("roles", [])
        if isinstance(roles, list) and "registrant" in roles:
            return True
    return False


# ---------------------------------------------------------------------------
# rdap-92: Service port consistency check
# ---------------------------------------------------------------------------

ORDER_INDEPENDENT_KEYS = frozenset({
    "entities",
    "events",
    "notices",
    "remarks",
    "links",
    "rdapConformance",
    "publicIDs",
    "status",
    "ipAddresses",
    "nameservers",
    "redactions",
})

LAST_UPDATE_EVENT_ACTION = "last update of RDAP database"


@dataclass(frozen=True)
class Rdap92Error:
    """Structured error produced by the rdap-92 service port consistency check."""

    code: str
    severity: str
    detail: str


@dataclass(frozen=True)
class ServicePort:
    """An (ip_address, port) pair with its address family."""

    ip: str
    port: int
    family: int  # socket.AF_INET or socket.AF_INET6


@dataclass
class Rdap92Result:
    """Aggregated result of an rdap-92 run."""

    passed: bool = True
    errors: list[Rdap92Error] = field(default_factory=list)
    service_ports_checked: list[ServicePort] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(Rdap92Error(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False


class DnsResolver:
    """Pluggable DNS resolver for testability."""

    def resolve(self, hostname: str, port: int) -> list[ServicePort]:
        service_ports: list[ServicePort] = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(hostname, port, family, socket.SOCK_STREAM)
                for _fam, _type, _proto, _canonname, sockaddr in results:
                    ip = sockaddr[0]
                    if not any(sp.ip == ip and sp.port == port for sp in service_ports):
                        service_ports.append(ServicePort(ip=ip, port=port, family=_fam))
            except socket.gaierror:
                continue
        return service_ports


class RdapServicePortQuerier:
    """Performs RDAP queries against a specific service port."""

    def __init__(self, session: requests.Session | None = None, timeout: int = 30) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    def query(self, *, base_url: str, service_port: ServicePort, path: str) -> dict[str, Any]:
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.hostname}:{service_port.port}{parsed.path}{path}"

        headers = {
            "Accept": "application/rdap+json, application/json",
            "Host": parsed.hostname or "",
        }

        response = self.session.get(url, headers=headers, timeout=self.timeout)
        if response.status_code != 200:
            raise RdapConformanceError(
                f"Service port {service_port.ip}:{service_port.port} returned "
                f"status {response.status_code} for {path}"
            )
        return response.json()


def canonicalize_rdap_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Produce a canonical form of an RDAP response for comparison.

    1. Remove "last update of RDAP database" events.
    2. Recursively sort values in order-independent keys.
    """
    result = copy.deepcopy(payload)
    _strip_last_update_events(result)
    _sort_order_independent_keys(result)
    return result


def _strip_last_update_events(obj: Any) -> None:
    if isinstance(obj, dict):
        events = obj.get("events")
        if isinstance(events, list):
            obj["events"] = [
                e for e in events
                if not (isinstance(e, dict) and e.get("eventAction") == LAST_UPDATE_EVENT_ACTION)
            ]
        for v in obj.values():
            _strip_last_update_events(v)
    elif isinstance(obj, list):
        for item in obj:
            _strip_last_update_events(item)


def _sort_order_independent_keys(obj: Any) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ORDER_INDEPENDENT_KEYS and isinstance(value, list):
                obj[key] = _sorted_json_list(value)
            else:
                _sort_order_independent_keys(value)
    elif isinstance(obj, list):
        for item in obj:
            _sort_order_independent_keys(item)


def _sorted_json_list(items: list[Any]) -> list[Any]:
    """Sort a list of arbitrary JSON values by their canonical JSON representation."""
    return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))


@dataclass(frozen=True)
class Rdap92Config:
    """Configuration for the rdap-92 service port consistency check."""

    base_urls: list[dict[str, str]]
    test_domains: list[dict[str, str]]
    test_entities: list[dict[str, str]]
    test_nameservers: list[dict[str, str]]
    timeout_seconds: int = 30


class ServicePortConsistencyChecker:
    """Implements rdap-92: verify all RDAP service ports return identical responses.

    For each RDAP base URL the checker:
    1. Resolves the hostname to discover all service ports (IPv4 + IPv6).
    2. Queries each service port for every test domain, entity, and nameserver.
    3. Canonicalizes each response (strips "last update of RDAP database" events,
       sorts order-independent arrays).
    4. Compares all canonicalized responses to ensure consistency.
    """

    def __init__(
        self,
        config: Rdap92Config,
        *,
        resolver: DnsResolver | None = None,
        querier: RdapServicePortQuerier | None = None,
    ) -> None:
        self.config = config
        self.resolver = resolver or DnsResolver()
        self.querier = querier or RdapServicePortQuerier(timeout=config.timeout_seconds)

    def run(self) -> Rdap92Result:
        result = Rdap92Result()

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]
            parsed = urlparse(base_url)
            hostname = parsed.hostname or ""
            port = parsed.port or 443

            service_ports = self._resolve_service_ports(hostname, port, result)
            if not service_ports:
                continue

            result.service_ports_checked.extend(service_ports)

            query_paths = self._build_query_paths(tld, base_url)
            for path_label, path in query_paths:
                self._check_consistency(
                    base_url=base_url,
                    service_ports=service_ports,
                    path=path,
                    path_label=path_label,
                    result=result,
                )

        return result

    def _resolve_service_ports(
        self, hostname: str, port: int, result: Rdap92Result
    ) -> list[ServicePort]:
        try:
            service_ports = self.resolver.resolve(hostname, port)
        except Exception as exc:
            result.add_error(
                "RDAP_TLS_DNS_RESOLUTION_ERROR",
                "ERROR",
                f"DNS resolution failed for {hostname}: {exc}",
            )
            return []

        if not service_ports:
            result.add_error(
                "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE",
                "CRITICAL",
                f"No service ports could be resolved for {hostname}",
            )
            return []

        return service_ports

    def _build_query_paths(
        self, tld: str, base_url: str
    ) -> list[tuple[str, str]]:
        paths: list[tuple[str, str]] = []

        for domain_entry in self.config.test_domains:
            if domain_entry["tld"] == tld:
                name = domain_entry["name"]
                paths.append((f"domain/{name}", f"domain/{name}"))

        for entity_entry in self.config.test_entities:
            if entity_entry["tld"] == tld:
                handle = entity_entry["handle"]
                paths.append((f"entity/{handle}", f"entity/{handle}"))

        for ns_entry in self.config.test_nameservers:
            if ns_entry["tld"] == tld:
                nameserver = ns_entry["nameserver"]
                paths.append((f"nameserver/{nameserver}", f"nameserver/{nameserver}"))

        return paths

    def _check_consistency(
        self,
        *,
        base_url: str,
        service_ports: list[ServicePort],
        path: str,
        path_label: str,
        result: Rdap92Result,
    ) -> None:
        responses: list[tuple[ServicePort, dict[str, Any]]] = []
        reachable_count = 0

        for sp in service_ports:
            try:
                payload = self.querier.query(
                    base_url=base_url,
                    service_port=sp,
                    path=path,
                )
                reachable_count += 1
                responses.append((sp, payload))
            except RdapConformanceError as exc:
                result.add_error(
                    "RDAP_QUERY_FAILED",
                    "ERROR",
                    f"Query for {path_label} on {sp.ip}:{sp.port} failed: {exc}",
                )
            except requests.RequestException as exc:
                result.add_error(
                    "RDAP_TLS_SERVICE_PORT_UNREACHABLE",
                    "ERROR",
                    f"Service port {sp.ip}:{sp.port} unreachable for {path_label}: {exc}",
                )

        if reachable_count == 0 and service_ports:
            result.add_error(
                "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE",
                "CRITICAL",
                f"No service ports reachable for {path_label}",
            )
            return

        if len(responses) < 2:
            return

        canonical_responses = [
            (sp, canonicalize_rdap_response(payload))
            for sp, payload in responses
        ]

        reference_sp, reference_canonical = canonical_responses[0]
        reference_json = json.dumps(reference_canonical, sort_keys=True, default=str)

        for sp, canonical in canonical_responses[1:]:
            compare_json = json.dumps(canonical, sort_keys=True, default=str)
            if compare_json != reference_json:
                result.add_error(
                    "RDAP_SERVICE_PORT_NOT_CONSISTENT",
                    "ERROR",
                    f"Response for {path_label} differs between "
                    f"{reference_sp.ip}:{reference_sp.port} and {sp.ip}:{sp.port}",
                )
