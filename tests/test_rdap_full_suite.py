"""Tests for rdap-01 through rdap-91 and the StandardRdapTestSuite runner.

Covers all RDAP test cases except rdap-92 (tested separately in
test_rdap_service_port_consistency.py).
"""
from __future__ import annotations

import json
import socket
from typing import Any
from unittest.mock import MagicMock

import pytest

from rst_compliance.rdap_conformance import (
    DnsResolver,
    DomainHeadChecker,
    DomainQueryChecker,
    EntityHeadChecker,
    EntityQueryChecker,
    HelpQueryChecker,
    NameserverHeadChecker,
    NameserverQueryChecker,
    NonExistentDomainChecker,
    NonExistentEntityChecker,
    NonExistentNameserverChecker,
    RdapHttpClient,
    RdapServicePortQuerier,
    RdapSuiteConfig,
    RdapTestResult,
    ServicePort,
    StandardRdapTestSuite,
    TlsConformanceChecker,
    TlsProbeResult,
    TlsProber,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def suite_config() -> RdapSuiteConfig:
    return RdapSuiteConfig(
        base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
        test_domains=[{"tld": "example", "name": "test.example"}],
        test_entities=[{"tld": "example", "handle": "9995"}],
        test_nameservers=[{"tld": "example", "nameserver": "ns1.example.com"}],
        registry_data_model="minimum",
        host_model="objects",
        timeout_seconds=10,
    )


DOMAIN_RESPONSE: dict[str, Any] = {
    "objectClassName": "domain",
    "ldhName": "test.example",
    "rdapConformance": ["rdap_level_0"],
    "links": [{"rel": "self", "href": "https://rdap.example.test/domain/test.example"}],
    "status": ["active"],
    "notices": [{"title": "ToS", "description": ["Terms"]}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]]},
    ],
}

NS_RESPONSE: dict[str, Any] = {
    "objectClassName": "nameserver",
    "ldhName": "ns1.example.com",
    "rdapConformance": ["rdap_level_0"],
    "links": [{"rel": "self", "href": "https://rdap.example.test/nameserver/ns1.example.com"}],
}

ENTITY_RESPONSE: dict[str, Any] = {
    "objectClassName": "entity",
    "handle": "9995",
    "rdapConformance": ["rdap_level_0"],
    "links": [{"rel": "self", "href": "https://rdap.example.test/entity/9995"}],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrar Inc."]]],
    "roles": ["registrar"],
}

HELP_RESPONSE: dict[str, Any] = {
    "rdapConformance": ["rdap_level_0"],
    "notices": [{"title": "Help", "description": ["RDAP help response"]}],
}

NOT_FOUND_BODY: dict[str, Any] = {
    "errorCode": 404,
    "title": "Not Found",
    "description": ["Object not found"],
}


# ---------------------------------------------------------------------------
# Stub HTTP client
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: dict[str, Any] | None = None,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.content = body if body else (json.dumps(payload).encode() if payload else b"")
        self.text = self.content.decode("utf-8") if self.content else ""
        self.headers = headers if headers is not None else {"access-control-allow-origin": "*"}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self) -> dict[str, Any]:
        return self._payload or {}


class StubHttpClient(RdapHttpClient):
    """Returns pre-configured responses based on URL patterns."""

    def __init__(self, responses: dict[str, _FakeResponse] | None = None) -> None:
        self._responses = responses or {}
        self._default_get: _FakeResponse | None = None
        self._default_head: _FakeResponse | None = None
        self.get_calls: list[str] = []
        self.head_calls: list[str] = []

    def set_default_get(self, resp: _FakeResponse) -> None:
        self._default_get = resp

    def set_default_head(self, resp: _FakeResponse) -> None:
        self._default_head = resp

    def get(self, url: str) -> _FakeResponse:  # type: ignore[override]
        self.get_calls.append(url)
        for pattern, resp in self._responses.items():
            if pattern in url:
                return resp
        if self._default_get:
            return self._default_get
        return _FakeResponse(status_code=500, payload={"error": "no stub"})

    def head(self, url: str) -> _FakeResponse:  # type: ignore[override]
        self.head_calls.append(url)
        # Check HEAD-specific responses first (prefixed with "HEAD:")
        for pattern, resp in self._responses.items():
            if pattern.startswith("HEAD:") and pattern[5:] in url:
                return resp
        if self._default_head:
            return self._default_head
        return _FakeResponse(status_code=500, body=b"")


# ===================================================================
# rdap-01: Domain query test
# ===================================================================


class TestRdap01DomainQuery:
    def test_valid_domain_response_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"domain/test.example": _FakeResponse(payload=DOMAIN_RESPONSE)})
        result = DomainQueryChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-01"
        assert result.passed

    def test_missing_object_class_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {**DOMAIN_RESPONSE, "objectClassName": "entity"}
        client = StubHttpClient({"domain/test.example": _FakeResponse(payload=bad)})
        result = DomainQueryChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_DOMAIN_RESPONSE_VALIDATION_FAILED" for e in result.errors)

    def test_missing_ldh_name_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {k: v for k, v in DOMAIN_RESPONSE.items() if k != "ldhName"}
        client = StubHttpClient({"domain/test.example": _FakeResponse(payload=bad)})
        result = DomainQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_maximum_model_requires_registrant(self) -> None:
        config = RdapSuiteConfig(
            base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
            test_domains=[{"tld": "example", "name": "test.example"}],
            test_entities=[], test_nameservers=[],
            registry_data_model="maximum",
        )
        no_registrant = {**DOMAIN_RESPONSE, "entities": [
            {"roles": ["technical"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]]},
        ]}
        client = StubHttpClient({"domain/test.example": _FakeResponse(payload=no_registrant)})
        result = DomainQueryChecker(config, client=client).run()
        assert not result.passed

    def test_http_error_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"domain/test.example": _FakeResponse(status_code=500, payload={})})
        result = DomainQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_filters_by_tld(self) -> None:
        config = RdapSuiteConfig(
            base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
            test_domains=[
                {"tld": "example", "name": "test.example"},
                {"tld": "other", "name": "test.other"},
            ],
            test_entities=[], test_nameservers=[],
        )
        client = StubHttpClient({"domain/test.example": _FakeResponse(payload=DOMAIN_RESPONSE)})
        client.set_default_get(_FakeResponse(status_code=500, payload={}))
        result = DomainQueryChecker(config, client=client).run()
        assert result.passed
        assert len(client.get_calls) == 1


# ===================================================================
# rdap-02: Nameserver query test
# ===================================================================


class TestRdap02NameserverQuery:
    def test_valid_nameserver_response_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"nameserver/ns1.example.com": _FakeResponse(payload=NS_RESPONSE)})
        result = NameserverQueryChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-02"
        assert result.passed

    def test_skipped_when_host_model_attributes(self) -> None:
        config = RdapSuiteConfig(
            base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
            test_domains=[], test_entities=[],
            test_nameservers=[{"tld": "example", "nameserver": "ns1.example.com"}],
            host_model="attributes",
        )
        result = NameserverQueryChecker(config).run()
        assert result.skipped
        assert result.test_id == "rdap-02"

    def test_wrong_object_class_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {**NS_RESPONSE, "objectClassName": "domain"}
        client = StubHttpClient({"nameserver/ns1.example.com": _FakeResponse(payload=bad)})
        result = NameserverQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_missing_ldh_name_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {k: v for k, v in NS_RESPONSE.items() if k != "ldhName"}
        client = StubHttpClient({"nameserver/ns1.example.com": _FakeResponse(payload=bad)})
        result = NameserverQueryChecker(suite_config, client=client).run()
        assert not result.passed


# ===================================================================
# rdap-03: Entity (registrar) query test
# ===================================================================


class TestRdap03EntityQuery:
    def test_valid_entity_response_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"entity/9995": _FakeResponse(payload=ENTITY_RESPONSE)})
        result = EntityQueryChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-03"
        assert result.passed

    def test_wrong_object_class_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {**ENTITY_RESPONSE, "objectClassName": "domain"}
        client = StubHttpClient({"entity/9995": _FakeResponse(payload=bad)})
        result = EntityQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_missing_handle_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {k: v for k, v in ENTITY_RESPONSE.items() if k != "handle"}
        client = StubHttpClient({"entity/9995": _FakeResponse(payload=bad)})
        result = EntityQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_missing_vcard_array_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {k: v for k, v in ENTITY_RESPONSE.items() if k != "vcardArray"}
        client = StubHttpClient({"entity/9995": _FakeResponse(payload=bad)})
        result = EntityQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_invalid_vcard_array_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {**ENTITY_RESPONSE, "vcardArray": ["notVcard", []]}
        client = StubHttpClient({"entity/9995": _FakeResponse(payload=bad)})
        result = EntityQueryChecker(suite_config, client=client).run()
        assert not result.passed


# ===================================================================
# rdap-04: Help query test
# ===================================================================


class TestRdap04HelpQuery:
    def test_valid_help_response_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"/help": _FakeResponse(payload=HELP_RESPONSE)})
        result = HelpQueryChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-04"
        assert result.passed

    def test_missing_rdap_conformance_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {"notices": [{"title": "Help"}]}
        client = StubHttpClient({"/help": _FakeResponse(payload=bad)})
        result = HelpQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_missing_notices_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {"rdapConformance": ["rdap_level_0"]}
        client = StubHttpClient({"/help": _FakeResponse(payload=bad)})
        result = HelpQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_empty_rdap_conformance_fails(self, suite_config: RdapSuiteConfig) -> None:
        bad = {"rdapConformance": [], "notices": [{"title": "Help"}]}
        client = StubHttpClient({"/help": _FakeResponse(payload=bad)})
        result = HelpQueryChecker(suite_config, client=client).run()
        assert not result.passed

    def test_http_error_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient({"/help": _FakeResponse(status_code=500, payload={})})
        result = HelpQueryChecker(suite_config, client=client).run()
        assert not result.passed


# ===================================================================
# rdap-05: Domain HEAD test
# ===================================================================


class TestRdap05DomainHead:
    def test_valid_head_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=200, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = DomainHeadChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-05"
        assert result.passed

    def test_non_200_status_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=404, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = DomainHeadChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_DOMAIN_HEAD_FAILED" for e in result.errors)

    def test_missing_cors_header_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(status_code=200, body=b"", headers={}))
        result = DomainHeadChecker(suite_config, client=client).run()
        assert not result.passed

    def test_non_empty_body_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=200, body=b"some body",
            headers={"access-control-allow-origin": "*"},
        ))
        result = DomainHeadChecker(suite_config, client=client).run()
        assert not result.passed


# ===================================================================
# rdap-06: Nameserver HEAD test
# ===================================================================


class TestRdap06NameserverHead:
    def test_valid_head_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=200, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = NameserverHeadChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-06"
        assert result.passed

    def test_skipped_when_host_model_attributes(self) -> None:
        config = RdapSuiteConfig(
            base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
            test_domains=[], test_entities=[],
            test_nameservers=[{"tld": "example", "nameserver": "ns1.example.com"}],
            host_model="attributes",
        )
        result = NameserverHeadChecker(config).run()
        assert result.skipped


# ===================================================================
# rdap-07: Entity HEAD test
# ===================================================================


class TestRdap07EntityHead:
    def test_valid_head_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=200, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = EntityHeadChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-07"
        assert result.passed

    def test_non_200_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_head(_FakeResponse(
            status_code=503, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = EntityHeadChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_ENTITY_HEAD_FAILED" for e in result.errors)


# ===================================================================
# rdap-08: Non-existent domain test
# ===================================================================


class TestRdap08NonExistentDomain:
    def test_404_with_valid_error_body_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404,
            payload=NOT_FOUND_BODY,
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-08"
        assert result.passed

    def test_404_with_empty_body_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404, body=b"",
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert result.passed

    def test_200_instead_of_404_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=200, payload=DOMAIN_RESPONSE,
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_DOMAIN" for e in result.errors)

    def test_404_missing_cors_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(status_code=404, body=b"", headers={}))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert not result.passed

    def test_404_with_invalid_json_body_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404, body=b"not json",
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert not result.passed

    def test_404_with_missing_error_code_field_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404, payload={"title": "Not Found"},
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentDomainChecker(suite_config, client=client).run()
        assert not result.passed


# ===================================================================
# rdap-09: Non-existent nameserver test
# ===================================================================


class TestRdap09NonExistentNameserver:
    def test_404_for_both_internal_and_external_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404,
            payload=NOT_FOUND_BODY,
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentNameserverChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-09"
        assert result.passed
        assert len(client.get_calls) == 2

    def test_non_404_for_internal_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        call_count = [0]
        original_get = client.get

        def side_effect_get(url: str) -> _FakeResponse:
            call_count[0] += 1
            if call_count[0] == 1:
                return _FakeResponse(
                    status_code=200, payload=NS_RESPONSE,
                    headers={"access-control-allow-origin": "*"},
                )
            return _FakeResponse(
                status_code=404, payload=NOT_FOUND_BODY,
                headers={"access-control-allow-origin": "*"},
            )

        client.get = side_effect_get  # type: ignore[assignment]
        result = NonExistentNameserverChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_NAMESERVER" for e in result.errors)


# ===================================================================
# rdap-10: Non-existent entity test
# ===================================================================


class TestRdap10NonExistentEntity:
    def test_404_passes(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=404,
            payload=NOT_FOUND_BODY,
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentEntityChecker(suite_config, client=client).run()
        assert result.test_id == "rdap-10"
        assert result.passed

    def test_non_404_fails(self, suite_config: RdapSuiteConfig) -> None:
        client = StubHttpClient()
        client.set_default_get(_FakeResponse(
            status_code=200, payload=ENTITY_RESPONSE,
            headers={"access-control-allow-origin": "*"},
        ))
        result = NonExistentEntityChecker(suite_config, client=client).run()
        assert not result.passed
        assert any(e.code == "RDAP_INVALID_RESPONSE_FOR_NON_EXISTENT_ENTITY" for e in result.errors)


# ===================================================================
# rdap-91: TLS conformance check
# ===================================================================


class StubTlsProber(TlsProber):
    def __init__(self, result: TlsProbeResult) -> None:
        self._result = result

    def probe(self, hostname: str, ip: str, port: int) -> TlsProbeResult:
        return self._result


class FailingTlsProber(TlsProber):
    def probe(self, hostname: str, ip: str, port: int) -> TlsProbeResult:
        raise ConnectionError(f"Cannot reach {ip}:{port}")


class StubDnsResolver(DnsResolver):
    def __init__(self, ports: list[ServicePort]) -> None:
        self._ports = ports

    def resolve(self, hostname: str, port: int) -> list[ServicePort]:
        return self._ports


TWO_PORTS = [
    ServicePort(ip="93.184.216.34", port=443, family=socket.AF_INET),
    ServicePort(ip="2606:2800:220:1:248:1893:25c8:1946", port=443, family=socket.AF_INET6),
]


class TestRdap91TlsConformance:
    def test_all_checks_pass(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult())
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert result.test_id == "rdap-91"
        assert result.passed
        assert not result.errors

    def test_tls_1_2_not_supported_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(supports_tls_1_2=False))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED" for e in result.errors)

    def test_forbidden_protocol_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(forbidden_protocols_supported=["TLSv1.0", "TLSv1.1"]))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        errors = [e for e in result.errors if e.code == "RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED"]
        assert len(errors) >= 2

    def test_untrusted_certificate_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(certificate_trusted=False))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_UNTRUSTED_CERTIFICATE" for e in result.errors)

    def test_expired_certificate_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(certificate_expired=True))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_EXPIRED_CERTIFICATE" for e in result.errors)

    def test_chain_missing_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(certificate_chain_complete=False))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_CERTIFICATE_CHAIN_MISSING" for e in result.errors)

    def test_hostname_mismatch_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(hostname_matches=False))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_CERTIFICATE_HOSTNAME_MISMATCH" for e in result.errors)

    def test_bad_cipher_fails(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(has_recommended_cipher=False))
        resolver = StubDnsResolver(TWO_PORTS)
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_BAD_CIPHER" for e in result.errors)

    def test_dns_resolution_error(self, suite_config: RdapSuiteConfig) -> None:
        class FailResolver(DnsResolver):
            def resolve(self, hostname: str, port: int) -> list[ServicePort]:
                raise socket.gaierror("DNS failed")
        result = TlsConformanceChecker(
            suite_config, resolver=FailResolver(), tls_prober=StubTlsProber(TlsProbeResult()),
        ).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_DNS_RESOLUTION_ERROR" for e in result.errors)

    def test_no_service_ports_resolved(self, suite_config: RdapSuiteConfig) -> None:
        result = TlsConformanceChecker(
            suite_config,
            resolver=StubDnsResolver([]),
            tls_prober=StubTlsProber(TlsProbeResult()),
        ).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE" for e in result.errors)

    def test_all_ports_unreachable(self, suite_config: RdapSuiteConfig) -> None:
        result = TlsConformanceChecker(
            suite_config,
            resolver=StubDnsResolver(TWO_PORTS),
            tls_prober=FailingTlsProber(),
        ).run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_SERVICE_PORT_UNREACHABLE" for e in result.errors)
        assert any(e.code == "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE" for e in result.errors)

    def test_multiple_failures_aggregated(self, suite_config: RdapSuiteConfig) -> None:
        prober = StubTlsProber(TlsProbeResult(
            supports_tls_1_2=False,
            certificate_expired=True,
            has_recommended_cipher=False,
        ))
        resolver = StubDnsResolver([TWO_PORTS[0]])
        result = TlsConformanceChecker(suite_config, resolver=resolver, tls_prober=prober).run()
        assert not result.passed
        codes = {e.code for e in result.errors}
        assert "RDAP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED" in codes
        assert "RDAP_TLS_EXPIRED_CERTIFICATE" in codes
        assert "RDAP_TLS_BAD_CIPHER" in codes


# ===================================================================
# RdapTestResult tests
# ===================================================================


class TestRdapTestResult:
    def test_initially_passes(self) -> None:
        r = RdapTestResult(test_id="rdap-01")
        assert r.passed and not r.skipped and not r.errors

    def test_skip(self) -> None:
        r = RdapTestResult(test_id="rdap-02")
        r.skip("not applicable")
        assert r.skipped
        assert len(r.errors) == 1
        assert r.errors[0].code == "SKIPPED"

    def test_add_error_sets_passed_false(self) -> None:
        r = RdapTestResult(test_id="rdap-01")
        r.add_error("TEST", "ERROR", "detail")
        assert not r.passed


# ===================================================================
# StandardRdapTestSuite integration test
# ===================================================================


def _build_full_suite_client() -> StubHttpClient:
    """Create a StubHttpClient that returns valid responses for all RDAP test cases."""
    client = StubHttpClient({
        "domain/test.example": _FakeResponse(payload=DOMAIN_RESPONSE),
        "nameserver/ns1.example.com": _FakeResponse(payload=NS_RESPONSE),
        "entity/9995": _FakeResponse(payload=ENTITY_RESPONSE),
        "/help": _FakeResponse(payload=HELP_RESPONSE),
    })
    client.set_default_get(_FakeResponse(
        status_code=404, payload=NOT_FOUND_BODY,
        headers={"access-control-allow-origin": "*"},
    ))
    client.set_default_head(_FakeResponse(
        status_code=200, body=b"",
        headers={"access-control-allow-origin": "*"},
    ))
    return client


class TestStandardRdapTestSuite:
    def test_runs_all_12_test_cases(self, suite_config: RdapSuiteConfig) -> None:
        client = _build_full_suite_client()

        prober = StubTlsProber(TlsProbeResult())
        resolver = StubDnsResolver(TWO_PORTS)

        querier = MagicMock(spec=RdapServicePortQuerier)
        querier.query.return_value = DOMAIN_RESPONSE

        suite = StandardRdapTestSuite(
            suite_config,
            client=client,
            resolver=resolver,
            querier=querier,
            tls_prober=prober,
        )
        results = suite.run_all()
        assert len(results) == 12

        test_ids = [r.test_id for r in results]
        for tid in [
            "rdap-01", "rdap-02", "rdap-03", "rdap-04",
            "rdap-05", "rdap-06", "rdap-07",
            "rdap-08", "rdap-09", "rdap-10",
            "rdap-91", "rdap-92",
        ]:
            assert tid in test_ids, f"Missing test: {tid}"

    def test_all_pass_when_responses_valid(self, suite_config: RdapSuiteConfig) -> None:
        client = _build_full_suite_client()

        prober = StubTlsProber(TlsProbeResult())
        resolver = StubDnsResolver(TWO_PORTS)
        querier = MagicMock(spec=RdapServicePortQuerier)
        querier.query.return_value = DOMAIN_RESPONSE

        suite = StandardRdapTestSuite(
            suite_config, client=client, resolver=resolver,
            querier=querier, tls_prober=prober,
        )
        results = suite.run_all()
        failing = [r for r in results if not r.passed and not r.skipped]
        assert not failing, f"Unexpected failures: {[(r.test_id, r.errors) for r in failing]}"
