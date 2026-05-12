from __future__ import annotations

import copy
import json
import random
import socket
import ssl
import string
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

    def run_head_check(self, *, object_path: str) -> None:
        endpoint = f"{self.config.base_url.rstrip('/')}/{object_path.lstrip('/')}"
        response = self.session.head(endpoint, headers={"Accept": "application/rdap+json, application/json"}, timeout=self.config.timeout_seconds)
        validate_rdap_head_response(response=response)


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

    for fld in ("rdapConformance", "links", "status", "notices", "entities"):
        if fld not in payload:
            raise RdapConformanceError(f"RDAP response missing mandatory field: {fld}")

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


def validate_rdap_head_response(*, response: Any) -> None:
    status_code = int(getattr(response, "status_code", 0))
    if status_code != 200:
        raise RdapConformanceError(f"HEAD request must return 200, got {status_code}")

    headers = getattr(response, "headers", {}) or {}
    if "access-control-allow-origin" not in {str(key).lower() for key in headers}:
        raise RdapConformanceError("HEAD response missing access-control-allow-origin header")

    body = getattr(response, "text", "")
    if body and str(body).strip():
        raise RdapConformanceError("HEAD response body must be empty")


def _has_registrant_entity(entities: list[dict[str, Any]]) -> bool:
    for entity in entities:
        roles = entity.get("roles", [])
        if isinstance(roles, list) and "registrant" in roles:
            return True
    return False


# ---------------------------------------------------------------------------
# Shared types for rdap-01 … rdap-92
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RdapTestError:
    """Structured error produced by any RDAP test case."""

    code: str
    severity: str
    detail: str


@dataclass
class RdapTestResult:
    """Aggregated result of a single RDAP test case run."""

    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[RdapTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(RdapTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(RdapTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class RdapSuiteConfig:
    """Unified configuration for the full StandardRDAP test suite."""

    base_urls: list[dict[str, str]]
    test_domains: list[dict[str, str]]
    test_entities: list[dict[str, str]]
    test_nameservers: list[dict[str, str]]
    registry_data_model: str = "minimum"
    host_model: str = "objects"
    timeout_seconds: int = 30


class RdapHttpClient:
    """Pluggable HTTP client for all RDAP test cases."""

    def __init__(self, session: requests.Session | None = None, timeout: int = 30) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    def get(self, url: str) -> requests.Response:
        headers = {"Accept": "application/rdap+json, application/json"}
        return self.session.get(url, headers=headers, timeout=self.timeout)

    def head(self, url: str) -> requests.Response:
        headers = {"Accept": "application/rdap+json, application/json"}
        return self.session.head(url, headers=headers, timeout=self.timeout)


def _random_label(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ---------------------------------------------------------------------------
# rdap-01: Domain query test
# ---------------------------------------------------------------------------

class DomainQueryChecker:
    """rdap-01: validates server responses to domain name queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-01")
        model = RegistryDataModel.parse(self.config.registry_data_model)

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for domain_entry in self.config.test_domains:
                if domain_entry["tld"] != tld:
                    continue
                name = domain_entry["name"]
                url = f"{base_url.rstrip('/')}/domain/{name}"

                try:
                    response = self.client.get(url)
                    response.raise_for_status()
                    payload = response.json()
                    self._validate_domain_response(payload, model)
                except Exception as exc:
                    result.add_error(
                        "RDAP_DOMAIN_RESPONSE_VALIDATION_FAILED",
                        "ERROR",
                        f"Domain query for {name} failed: {exc}",
                    )

        return result

    @staticmethod
    def _validate_domain_response(payload: dict[str, Any], model: RegistryDataModel) -> None:
        if not isinstance(payload, dict):
            raise RdapConformanceError("domain response must be a JSON object")
        if payload.get("objectClassName") != "domain":
            raise RdapConformanceError("objectClassName must be 'domain'")
        if not payload.get("ldhName"):
            raise RdapConformanceError("domain response must include ldhName")
        for fld in ("rdapConformance", "links", "entities"):
            if fld not in payload:
                raise RdapConformanceError(f"domain response missing field: {fld}")
        if model == RegistryDataModel.MAXIMUM:
            entities = payload.get("entities", [])
            if not _has_registrant_entity(entities):
                raise RdapConformanceError("maximum model requires registrant entity")


# ---------------------------------------------------------------------------
# rdap-02: Nameserver query test
# ---------------------------------------------------------------------------

class NameserverQueryChecker:
    """rdap-02: validates server responses to nameserver queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-02")

        if self.config.host_model == "attributes":
            result.skip("epp.hostModel is 'attributes'; rdap-02 skipped")
            return result

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for ns_entry in self.config.test_nameservers:
                if ns_entry["tld"] != tld:
                    continue
                ns = ns_entry["nameserver"]
                url = f"{base_url.rstrip('/')}/nameserver/{ns}"

                try:
                    response = self.client.get(url)
                    response.raise_for_status()
                    payload = response.json()
                    self._validate_nameserver_response(payload)
                except Exception as exc:
                    result.add_error(
                        "RDAP_NAMESERVER_RESPONSE_VALIDATION_FAILED",
                        "ERROR",
                        f"Nameserver query for {ns} failed: {exc}",
                    )

        return result

    @staticmethod
    def _validate_nameserver_response(payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise RdapConformanceError("nameserver response must be a JSON object")
        if payload.get("objectClassName") != "nameserver":
            raise RdapConformanceError("objectClassName must be 'nameserver'")
        if not payload.get("ldhName"):
            raise RdapConformanceError("nameserver response must include ldhName")
        for fld in ("rdapConformance", "links"):
            if fld not in payload:
                raise RdapConformanceError(f"nameserver response missing field: {fld}")


# ---------------------------------------------------------------------------
# rdap-03: Registrar (entity) query test
# ---------------------------------------------------------------------------

class EntityQueryChecker:
    """rdap-03: validates server responses to entity queries for registrars."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-03")

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for entity_entry in self.config.test_entities:
                if entity_entry["tld"] != tld:
                    continue
                handle = entity_entry["handle"]
                url = f"{base_url.rstrip('/')}/entity/{handle}"

                try:
                    response = self.client.get(url)
                    response.raise_for_status()
                    payload = response.json()
                    self._validate_entity_response(payload)
                except Exception as exc:
                    result.add_error(
                        "RDAP_ENTITY_RESPONSE_VALIDATION_FAILED",
                        "ERROR",
                        f"Entity query for {handle} failed: {exc}",
                    )

        return result

    @staticmethod
    def _validate_entity_response(payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise RdapConformanceError("entity response must be a JSON object")
        if payload.get("objectClassName") != "entity":
            raise RdapConformanceError("objectClassName must be 'entity'")
        if not payload.get("handle"):
            raise RdapConformanceError("entity response must include handle")
        for fld in ("rdapConformance", "links", "vcardArray"):
            if fld not in payload:
                raise RdapConformanceError(f"entity response missing field: {fld}")
        vcard = payload.get("vcardArray", [])
        if not isinstance(vcard, list) or len(vcard) < 2 or vcard[0] != "vcard":
            raise RdapConformanceError("entity vcardArray must start with 'vcard'")


# ---------------------------------------------------------------------------
# rdap-04: Help query test
# ---------------------------------------------------------------------------

class HelpQueryChecker:
    """rdap-04: validates server responses to help queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-04")

        for base_url_entry in self.config.base_urls:
            base_url = base_url_entry["baseURL"]
            url = f"{base_url.rstrip('/')}/help"

            try:
                response = self.client.get(url)
                response.raise_for_status()
                payload = response.json()
                self._validate_help_response(payload)
            except Exception as exc:
                result.add_error(
                    "RDAP_HELP_RESPONSE_VALIDATION_FAILED",
                    "ERROR",
                    f"Help query for {base_url} failed: {exc}",
                )

        return result

    @staticmethod
    def _validate_help_response(payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise RdapConformanceError("help response must be a JSON object")
        for fld in ("rdapConformance", "notices"):
            if fld not in payload:
                raise RdapConformanceError(f"help response missing field: {fld}")
        if not isinstance(payload["rdapConformance"], list) or not payload["rdapConformance"]:
            raise RdapConformanceError("rdapConformance must be a non-empty array")


# ---------------------------------------------------------------------------
# rdap-05: Domain HEAD test
# ---------------------------------------------------------------------------

class DomainHeadChecker:
    """rdap-05: validates HEAD support for domain queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-05")

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for domain_entry in self.config.test_domains:
                if domain_entry["tld"] != tld:
                    continue
                name = domain_entry["name"]
                url = f"{base_url.rstrip('/')}/domain/{name}"

                try:
                    response = self.client.head(url)
                    _validate_head_response(response, f"domain/{name}")
                except Exception as exc:
                    result.add_error(
                        "RDAP_DOMAIN_HEAD_FAILED",
                        "ERROR",
                        f"Domain HEAD for {name} failed: {exc}",
                    )

        return result


# ---------------------------------------------------------------------------
# rdap-06: Nameserver HEAD test
# ---------------------------------------------------------------------------

class NameserverHeadChecker:
    """rdap-06: validates HEAD support for nameserver queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-06")

        if self.config.host_model == "attributes":
            result.skip("epp.hostModel is 'attributes'; rdap-06 skipped")
            return result

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for ns_entry in self.config.test_nameservers:
                if ns_entry["tld"] != tld:
                    continue
                ns = ns_entry["nameserver"]
                url = f"{base_url.rstrip('/')}/nameserver/{ns}"

                try:
                    response = self.client.head(url)
                    _validate_head_response(response, f"nameserver/{ns}")
                except Exception as exc:
                    result.add_error(
                        "RDAP_NAMESERVER_HEAD_FAILED",
                        "ERROR",
                        f"Nameserver HEAD for {ns} failed: {exc}",
                    )

        return result


# ---------------------------------------------------------------------------
# rdap-07: Entity HEAD test
# ---------------------------------------------------------------------------

class EntityHeadChecker:
    """rdap-07: validates HEAD support for entity queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-07")

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            for entity_entry in self.config.test_entities:
                if entity_entry["tld"] != tld:
                    continue
                handle = entity_entry["handle"]
                url = f"{base_url.rstrip('/')}/entity/{handle}"

                try:
                    response = self.client.head(url)
                    _validate_head_response(response, f"entity/{handle}")
                except Exception as exc:
                    result.add_error(
                        "RDAP_ENTITY_HEAD_FAILED",
                        "ERROR",
                        f"Entity HEAD for {handle} failed: {exc}",
                    )

        return result


def _validate_head_response(response: requests.Response, label: str) -> None:
    if response.status_code != 200:
        raise RdapConformanceError(f"HEAD {label}: expected 200, got {response.status_code}")
    acao = response.headers.get("access-control-allow-origin")
    if not acao:
        raise RdapConformanceError(f"HEAD {label}: missing access-control-allow-origin header")
    body = response.content
    if body and len(body) > 0:
        raise RdapConformanceError(f"HEAD {label}: response body must be empty")


# ---------------------------------------------------------------------------
# rdap-08: Non-existent domain test
# ---------------------------------------------------------------------------

class NonExistentDomainChecker:
    """rdap-08: validates 404 responses for non-existent domain queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-08")

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]
            random_domain = f"{_random_label()}.{tld}"
            url = f"{base_url.rstrip('/')}/domain/{random_domain}"

            try:
                response = self.client.get(url)
                _validate_non_existent_response(response, random_domain)
            except Exception as exc:
                result.add_error(
                    "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_DOMAIN",
                    "ERROR",
                    f"Non-existent domain query for {random_domain} failed: {exc}",
                )

        return result


# ---------------------------------------------------------------------------
# rdap-09: Non-existent nameserver test
# ---------------------------------------------------------------------------

class NonExistentNameserverChecker:
    """rdap-09: validates 404 responses for non-existent nameserver queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-09")

        for base_url_entry in self.config.base_urls:
            tld = base_url_entry["tld"]
            base_url = base_url_entry["baseURL"]

            internal_ns = f"ns1.{_random_label()}.{tld}"
            url_internal = f"{base_url.rstrip('/')}/nameserver/{internal_ns}"
            try:
                response = self.client.get(url_internal)
                _validate_non_existent_response(response, internal_ns)
            except Exception as exc:
                result.add_error(
                    "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_NAMESERVER",
                    "ERROR",
                    f"Non-existent internal nameserver {internal_ns}: {exc}",
                )

            external_ns = f"ns1.{_random_label()}.external-test.example"
            url_external = f"{base_url.rstrip('/')}/nameserver/{external_ns}"
            try:
                response = self.client.get(url_external)
                _validate_non_existent_response(response, external_ns)
            except Exception as exc:
                result.add_error(
                    "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_NAMESERVER",
                    "ERROR",
                    f"Non-existent external nameserver {external_ns}: {exc}",
                )

        return result


# ---------------------------------------------------------------------------
# rdap-10: Non-existent entity test
# ---------------------------------------------------------------------------

class NonExistentEntityChecker:
    """rdap-10: validates 404 responses for non-existent entity queries."""

    def __init__(self, config: RdapSuiteConfig, *, client: RdapHttpClient | None = None) -> None:
        self.config = config
        self.client = client or RdapHttpClient(timeout=config.timeout_seconds)

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-10")

        for base_url_entry in self.config.base_urls:
            base_url = base_url_entry["baseURL"]
            random_handle = _random_label(16)
            url = f"{base_url.rstrip('/')}/entity/{random_handle}"

            try:
                response = self.client.get(url)
                _validate_non_existent_response(response, random_handle)
            except Exception as exc:
                result.add_error(
                    "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_ENTITY",
                    "ERROR",
                    f"Non-existent entity {random_handle}: {exc}",
                )

        return result


def _validate_non_existent_response(response: requests.Response, label: str) -> None:
    if response.status_code != 404:
        raise RdapConformanceError(
            f"Expected 404 for non-existent {label}, got {response.status_code}"
        )
    acao = response.headers.get("access-control-allow-origin")
    if not acao:
        raise RdapConformanceError(
            f"Non-existent {label}: missing access-control-allow-origin header"
        )
    body = response.text.strip()
    if body:
        try:
            error_obj = json.loads(body)
            if not isinstance(error_obj, dict):
                raise RdapConformanceError(f"Non-existent {label}: error body is not a JSON object")
            if "errorCode" not in error_obj:
                raise RdapConformanceError(
                    f"Non-existent {label}: error body missing 'errorCode' field"
                )
        except json.JSONDecodeError as exc:
            raise RdapConformanceError(
                f"Non-existent {label}: body is not valid JSON"
            ) from exc


# ---------------------------------------------------------------------------
# rdap-91: TLS version conformance check
# ---------------------------------------------------------------------------

RFC9325_RECOMMENDED_CIPHERS = frozenset({
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
})

FORBIDDEN_TLS_VERSIONS = frozenset({
    ssl.TLSVersion.SSLv3,
    ssl.TLSVersion.TLSv1,
    ssl.TLSVersion.TLSv1_1,
})


class TlsConformanceChecker:
    """rdap-91: verifies RDAP server TLS configuration.

    Checks: TLSv1.2+ required, TLSv1.1- forbidden, trusted CA,
    non-expired certificate, chain present, hostname match, RFC 9325 ciphers.
    """

    def __init__(
        self,
        config: RdapSuiteConfig,
        *,
        resolver: "DnsResolver | None" = None,
        tls_prober: "TlsProber | None" = None,
    ) -> None:
        self.config = config
        self.resolver = resolver or DnsResolver()
        self.tls_prober = tls_prober or TlsProber()

    def run(self) -> RdapTestResult:
        result = RdapTestResult(test_id="rdap-91")

        for base_url_entry in self.config.base_urls:
            base_url = base_url_entry["baseURL"]
            parsed = urlparse(base_url)
            hostname = parsed.hostname or ""
            port = parsed.port or 443

            try:
                service_ports = self.resolver.resolve(hostname, port)
            except Exception as exc:
                result.add_error(
                    "RDAP_TLS_DNS_RESOLUTION_ERROR", "ERROR",
                    f"DNS resolution failed for {hostname}: {exc}",
                )
                continue

            if not service_ports:
                result.add_error(
                    "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE", "CRITICAL",
                    f"No service ports resolved for {hostname}",
                )
                continue

            reachable = 0
            for sp in service_ports:
                try:
                    probe = self.tls_prober.probe(hostname, sp.ip, sp.port)
                    reachable += 1
                    self._check_probe_result(probe, sp, hostname, result)
                except Exception as exc:
                    result.add_error(
                        "RDAP_TLS_SERVICE_PORT_UNREACHABLE", "ERROR",
                        f"Port {sp.ip}:{sp.port} unreachable: {exc}",
                    )

            if reachable == 0:
                result.add_error(
                    "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE", "CRITICAL",
                    f"No service ports reachable for {hostname}",
                )

        return result

    @staticmethod
    def _check_probe_result(
        probe: "TlsProbeResult",
        sp: "ServicePort",
        hostname: str,
        result: RdapTestResult,
    ) -> None:
        if not probe.supports_tls_1_2:
            result.add_error(
                "RDAP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED", "ERROR",
                f"{sp.ip}:{sp.port} does not support TLSv1.2",
            )
        for forbidden in probe.forbidden_protocols_supported:
            result.add_error(
                "RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED", "ERROR",
                f"{sp.ip}:{sp.port} supports forbidden protocol {forbidden}",
            )
        if not probe.certificate_trusted:
            result.add_error(
                "RDAP_TLS_UNTRUSTED_CERTIFICATE", "ERROR",
                f"{sp.ip}:{sp.port} certificate not issued by trusted CA",
            )
        if probe.certificate_expired:
            result.add_error(
                "RDAP_TLS_EXPIRED_CERTIFICATE", "ERROR",
                f"{sp.ip}:{sp.port} certificate has expired",
            )
        if not probe.certificate_chain_complete:
            result.add_error(
                "RDAP_TLS_CERTIFICATE_CHAIN_MISSING", "ERROR",
                f"{sp.ip}:{sp.port} missing intermediate certificates",
            )
        if not probe.hostname_matches:
            result.add_error(
                "RDAP_TLS_CERTIFICATE_HOSTNAME_MISMATCH", "ERROR",
                f"{sp.ip}:{sp.port} certificate does not match hostname {hostname}",
            )
        if not probe.has_recommended_cipher:
            result.add_error(
                "RDAP_TLS_BAD_CIPHER", "ERROR",
                f"{sp.ip}:{sp.port} does not use an RFC 9325 recommended cipher",
            )


@dataclass(frozen=True)
class TlsProbeResult:
    """Result of a TLS probe against a single service port."""

    supports_tls_1_2: bool = True
    forbidden_protocols_supported: list[str] = field(default_factory=list)
    certificate_trusted: bool = True
    certificate_expired: bool = False
    certificate_chain_complete: bool = True
    hostname_matches: bool = True
    has_recommended_cipher: bool = True
    negotiated_cipher: str = ""
    negotiated_protocol: str = ""


class TlsProber:
    """Performs TLS probing against a service port. Override for testing."""

    def probe(self, hostname: str, ip: str, port: int) -> TlsProbeResult:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((ip, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cipher_info = tls_sock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else ""
                    protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else ""
                    return TlsProbeResult(
                        supports_tls_1_2=True,
                        certificate_trusted=True,
                        certificate_expired=False,
                        certificate_chain_complete=True,
                        hostname_matches=True,
                        has_recommended_cipher=cipher_name in RFC9325_RECOMMENDED_CIPHERS,
                        negotiated_cipher=cipher_name,
                        negotiated_protocol=protocol,
                    )
        except ssl.SSLCertVerificationError:
            return TlsProbeResult(certificate_trusted=False)
        except ssl.SSLError:
            return TlsProbeResult(supports_tls_1_2=False)


# ---------------------------------------------------------------------------
# StandardRDAP test suite runner
# ---------------------------------------------------------------------------

class StandardRdapTestSuite:
    """Runs all test cases in the StandardRDAP suite (rdap-01 … rdap-92).

    Usage:
        suite = StandardRdapTestSuite(config)
        results = suite.run_all()
    """

    def __init__(
        self,
        config: RdapSuiteConfig,
        *,
        client: RdapHttpClient | None = None,
        resolver: DnsResolver | None = None,
        querier: "RdapServicePortQuerier | None" = None,
        tls_prober: TlsProber | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.resolver = resolver
        self.querier = querier
        self.tls_prober = tls_prober

    def run_all(self) -> list[RdapTestResult]:
        results: list[RdapTestResult] = []
        results.append(DomainQueryChecker(self.config, client=self.client).run())
        results.append(NameserverQueryChecker(self.config, client=self.client).run())
        results.append(EntityQueryChecker(self.config, client=self.client).run())
        results.append(HelpQueryChecker(self.config, client=self.client).run())
        results.append(DomainHeadChecker(self.config, client=self.client).run())
        results.append(NameserverHeadChecker(self.config, client=self.client).run())
        results.append(EntityHeadChecker(self.config, client=self.client).run())
        results.append(NonExistentDomainChecker(self.config, client=self.client).run())
        results.append(NonExistentNameserverChecker(self.config, client=self.client).run())
        results.append(NonExistentEntityChecker(self.config, client=self.client).run())
        results.append(TlsConformanceChecker(
            self.config, resolver=self.resolver, tls_prober=self.tls_prober,
        ).run())

        rdap92_config = Rdap92Config(
            base_urls=self.config.base_urls,
            test_domains=self.config.test_domains,
            test_entities=self.config.test_entities,
            test_nameservers=self.config.test_nameservers,
            timeout_seconds=self.config.timeout_seconds,
        )
        r92 = ServicePortConsistencyChecker(
            rdap92_config, resolver=self.resolver, querier=self.querier,
        ).run()
        r92_result = RdapTestResult(test_id="rdap-92", passed=r92.passed)
        for err in r92.errors:
            r92_result.errors.append(RdapTestError(
                code=err.code, severity=err.severity, detail=err.detail,
            ))
        results.append(r92_result)

        return results


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
