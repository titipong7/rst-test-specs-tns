"""Tests for rdap-92: Service port consistency check.

Validates that ServicePortConsistencyChecker correctly:
- resolves RDAP base URL hostnames into IPv4/IPv6 service ports,
- queries each service port for test domains/entities/nameservers,
- canonicalizes responses (strips "last update of RDAP database" events,
  sorts order-independent arrays),
- compares responses across service ports and raises appropriate errors.
"""
from __future__ import annotations

import copy
import socket
from typing import Any

import pytest

from rst_compliance.rdap_conformance import (
    LAST_UPDATE_EVENT_ACTION,
    ORDER_INDEPENDENT_KEYS,
    DnsResolver,
    Rdap92Config,
    Rdap92Error,
    Rdap92Result,
    RdapConformanceError,
    RdapServicePortQuerier,
    ServicePort,
    ServicePortConsistencyChecker,
    canonicalize_rdap_response,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_DOMAIN_RESPONSE: dict[str, Any] = {
    "objectClassName": "domain",
    "ldhName": "example.example",
    "rdapConformance": ["rdap_level_0", "icann_rdap_response_profile_0"],
    "links": [
        {
            "value": "https://rdap.example.test/domain/example.example",
            "rel": "self",
            "href": "https://rdap.example.test/domain/example.example",
            "type": "application/rdap+json",
        }
    ],
    "status": ["active", "server delete prohibited"],
    "notices": [{"title": "ToS", "description": ["Terms of Service"]}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
        },
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"]]],
        },
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        {"eventAction": LAST_UPDATE_EVENT_ACTION, "eventDate": "2026-05-10T12:00:00Z"},
    ],
    "nameservers": [
        {"ldhName": "ns2.example.com"},
        {"ldhName": "ns1.example.com"},
    ],
}


@pytest.fixture
def base_config() -> Rdap92Config:
    return Rdap92Config(
        base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
        test_domains=[{"tld": "example", "name": "example.example"}],
        test_entities=[{"tld": "example", "handle": "9995"}],
        test_nameservers=[{"tld": "example", "nameserver": "ns1.example.com"}],
        timeout_seconds=10,
    )


# ---------------------------------------------------------------------------
# Stub resolver and querier
# ---------------------------------------------------------------------------

class StubResolver(DnsResolver):
    def __init__(self, ports: list[ServicePort]) -> None:
        self._ports = ports

    def resolve(self, hostname: str, port: int) -> list[ServicePort]:
        return self._ports


class FailingResolver(DnsResolver):
    def resolve(self, hostname: str, port: int) -> list[ServicePort]:
        raise socket.gaierror("DNS resolution failed")


class EmptyResolver(DnsResolver):
    def resolve(self, hostname: str, port: int) -> list[ServicePort]:
        return []


class StubQuerier(RdapServicePortQuerier):
    """Returns pre-configured responses keyed by (ip, path)."""

    def __init__(self, responses: dict[tuple[str, str], dict[str, Any]] | None = None) -> None:
        self._responses = responses or {}
        self._default_response: dict[str, Any] | None = None
        self.calls: list[tuple[str, ServicePort, str]] = []

    def set_default(self, response: dict[str, Any]) -> None:
        self._default_response = response

    def query(
        self, *, base_url: str, service_port: ServicePort, path: str
    ) -> dict[str, Any]:
        self.calls.append((base_url, service_port, path))
        key = (service_port.ip, path)
        if key in self._responses:
            return copy.deepcopy(self._responses[key])
        if self._default_response is not None:
            return copy.deepcopy(self._default_response)
        raise RdapConformanceError(f"No response configured for {key}")


class UnreachableQuerier(RdapServicePortQuerier):
    """Simulates all service ports being unreachable."""

    def query(
        self, *, base_url: str, service_port: ServicePort, path: str
    ) -> dict[str, Any]:
        import requests as _req
        raise _req.ConnectionError(
            f"Cannot reach {service_port.ip}:{service_port.port}"
        )


# ---------------------------------------------------------------------------
# Standard service ports for tests
# ---------------------------------------------------------------------------

IPV4_PORT = ServicePort(ip="93.184.216.34", port=443, family=socket.AF_INET)
IPV6_PORT = ServicePort(ip="2606:2800:220:1:248:1893:25c8:1946", port=443, family=socket.AF_INET6)
TWO_PORTS = [IPV4_PORT, IPV6_PORT]


# ===================================================================
# canonicalize_rdap_response tests
# ===================================================================


class TestCanonicalizeRdapResponse:
    def test_strips_last_update_event(self) -> None:
        payload: dict[str, Any] = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": LAST_UPDATE_EVENT_ACTION, "eventDate": "2026-05-10T12:00:00Z"},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert len(canonical["events"]) == 1
        assert canonical["events"][0]["eventAction"] == "registration"

    def test_preserves_other_events(self) -> None:
        payload: dict[str, Any] = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert len(canonical["events"]) == 2

    def test_sorts_order_independent_arrays(self) -> None:
        payload: dict[str, Any] = {
            "status": ["server delete prohibited", "active"],
            "rdapConformance": ["icann_rdap_response_profile_0", "rdap_level_0"],
        }
        canonical = canonicalize_rdap_response(payload)
        assert canonical["status"] == ["active", "server delete prohibited"]
        assert canonical["rdapConformance"] == ["icann_rdap_response_profile_0", "rdap_level_0"]

    def test_sorts_nested_entities(self) -> None:
        payload: dict[str, Any] = {
            "entities": [
                {"roles": ["technical"], "vcardArray": ["vcard", []]},
                {"roles": ["registrant"], "vcardArray": ["vcard", []]},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert canonical["entities"][0]["roles"] == ["registrant"]
        assert canonical["entities"][1]["roles"] == ["technical"]

    def test_does_not_modify_original(self) -> None:
        payload: dict[str, Any] = {
            "events": [
                {"eventAction": LAST_UPDATE_EVENT_ACTION, "eventDate": "2026-05-10T12:00:00Z"},
            ],
            "status": ["b", "a"],
        }
        original = copy.deepcopy(payload)
        canonicalize_rdap_response(payload)
        assert payload == original

    def test_handles_deeply_nested_last_update(self) -> None:
        payload: dict[str, Any] = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "events": [
                        {"eventAction": LAST_UPDATE_EVENT_ACTION, "eventDate": "2026-05-10T12:00:00Z"},
                        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    ],
                }
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert len(canonical["entities"][0]["events"]) == 1
        assert canonical["entities"][0]["events"][0]["eventAction"] == "registration"

    def test_handles_empty_events_list(self) -> None:
        payload: dict[str, Any] = {"events": []}
        canonical = canonicalize_rdap_response(payload)
        assert canonical["events"] == []

    def test_handles_payload_without_order_independent_keys(self) -> None:
        payload: dict[str, Any] = {"objectClassName": "domain", "ldhName": "test.example"}
        canonical = canonicalize_rdap_response(payload)
        assert canonical == payload

    def test_sorts_nameservers_array(self) -> None:
        payload: dict[str, Any] = {
            "nameservers": [
                {"ldhName": "ns2.example.com"},
                {"ldhName": "ns1.example.com"},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert canonical["nameservers"][0]["ldhName"] == "ns1.example.com"
        assert canonical["nameservers"][1]["ldhName"] == "ns2.example.com"

    def test_sorts_links_array(self) -> None:
        payload: dict[str, Any] = {
            "links": [
                {"rel": "related", "href": "https://example.com/related"},
                {"rel": "self", "href": "https://example.com/self"},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert canonical["links"][0]["rel"] == "related"
        assert canonical["links"][1]["rel"] == "self"

    def test_sorts_redactions_array(self) -> None:
        payload: dict[str, Any] = {
            "redactions": [
                {"name": {"description": "Registrant phone"}},
                {"name": {"description": "Registrant email"}},
            ]
        }
        canonical = canonicalize_rdap_response(payload)
        assert "email" in str(canonical["redactions"][0])
        assert "phone" in str(canonical["redactions"][1])


# ===================================================================
# DNS resolution tests
# ===================================================================


class TestDnsResolution:
    def test_dns_resolution_error_produces_error(self, base_config: Rdap92Config) -> None:
        checker = ServicePortConsistencyChecker(
            base_config, resolver=FailingResolver(), querier=StubQuerier()
        )
        result = checker.run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_DNS_RESOLUTION_ERROR" for e in result.errors)

    def test_no_service_ports_resolved_produces_critical(self, base_config: Rdap92Config) -> None:
        checker = ServicePortConsistencyChecker(
            base_config, resolver=EmptyResolver(), querier=StubQuerier()
        )
        result = checker.run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE" for e in result.errors)

    def test_resolved_ports_are_recorded(self, base_config: Rdap92Config) -> None:
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert len(result.service_ports_checked) == 2
        families = {sp.family for sp in result.service_ports_checked}
        assert socket.AF_INET in families
        assert socket.AF_INET6 in families


# ===================================================================
# Query path construction tests
# ===================================================================


class TestQueryPaths:
    def test_queries_all_object_types(self, base_config: Rdap92Config) -> None:
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        checker.run()

        paths_queried = {call[2] for call in querier.calls}
        assert "domain/example.example" in paths_queried
        assert "entity/9995" in paths_queried
        assert "nameserver/ns1.example.com" in paths_queried

    def test_queries_each_port_for_each_path(self, base_config: Rdap92Config) -> None:
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        checker.run()

        # 3 paths (domain, entity, nameserver) x 2 ports = 6 calls
        assert len(querier.calls) == 6

    def test_filters_by_tld(self) -> None:
        config = Rdap92Config(
            base_urls=[{"tld": "example", "baseURL": "https://rdap.example.test/"}],
            test_domains=[
                {"tld": "example", "name": "example.example"},
                {"tld": "other", "name": "other.other"},
            ],
            test_entities=[{"tld": "example", "handle": "9995"}],
            test_nameservers=[{"tld": "other", "nameserver": "ns1.other.com"}],
        )
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        checker.run()

        paths_queried = {call[2] for call in querier.calls}
        assert "domain/example.example" in paths_queried
        assert "entity/9995" in paths_queried
        assert "domain/other.other" not in paths_queried
        assert "nameserver/ns1.other.com" not in paths_queried


# ===================================================================
# Consistency check tests
# ===================================================================


class TestConsistency:
    def test_identical_responses_pass(self, base_config: Rdap92Config) -> None:
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert result.passed
        assert not result.errors

    def test_responses_differing_only_in_last_update_event_pass(
        self, base_config: Rdap92Config
    ) -> None:
        response_a = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b["events"][1]["eventDate"] = "2026-05-11T00:00:00Z"

        querier = StubQuerier({
            (IPV4_PORT.ip, "domain/example.example"): response_a,
            (IPV6_PORT.ip, "domain/example.example"): response_b,
            (IPV4_PORT.ip, "entity/9995"): response_a,
            (IPV6_PORT.ip, "entity/9995"): response_b,
            (IPV4_PORT.ip, "nameserver/ns1.example.com"): response_a,
            (IPV6_PORT.ip, "nameserver/ns1.example.com"): response_b,
        })
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert result.passed
        assert not any(e.code == "RDAP_SERVICE_PORT_NOT_CONSISTENT" for e in result.errors)

    def test_responses_with_different_array_order_pass(
        self, base_config: Rdap92Config
    ) -> None:
        response_a = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b["status"] = list(reversed(response_a["status"]))
        response_b["entities"] = list(reversed(response_a["entities"]))
        response_b["nameservers"] = list(reversed(response_a["nameservers"]))

        querier = StubQuerier({
            (IPV4_PORT.ip, "domain/example.example"): response_a,
            (IPV6_PORT.ip, "domain/example.example"): response_b,
            (IPV4_PORT.ip, "entity/9995"): response_a,
            (IPV6_PORT.ip, "entity/9995"): response_b,
            (IPV4_PORT.ip, "nameserver/ns1.example.com"): response_a,
            (IPV6_PORT.ip, "nameserver/ns1.example.com"): response_b,
        })
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert result.passed

    def test_substantive_difference_fails(self, base_config: Rdap92Config) -> None:
        response_a = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b["status"] = ["inactive"]

        querier = StubQuerier({
            (IPV4_PORT.ip, "domain/example.example"): response_a,
            (IPV6_PORT.ip, "domain/example.example"): response_b,
        })
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert not result.passed
        consistency_errors = [e for e in result.errors if e.code == "RDAP_SERVICE_PORT_NOT_CONSISTENT"]
        assert len(consistency_errors) >= 1
        assert "domain/example.example" in consistency_errors[0].detail

    def test_different_entity_content_fails(self, base_config: Rdap92Config) -> None:
        response_a = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b = copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)
        response_b["entities"][0]["roles"] = ["abuse"]

        querier = StubQuerier({
            (IPV4_PORT.ip, "domain/example.example"): response_a,
            (IPV6_PORT.ip, "domain/example.example"): response_b,
        })
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert not result.passed
        assert any(e.code == "RDAP_SERVICE_PORT_NOT_CONSISTENT" for e in result.errors)


# ===================================================================
# Service port unreachable and query failure tests
# ===================================================================


class TestServicePortErrors:
    def test_all_ports_unreachable_produces_critical(self, base_config: Rdap92Config) -> None:
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=UnreachableQuerier()
        )
        result = checker.run()
        assert not result.passed
        assert any(e.code == "RDAP_TLS_SERVICE_PORT_UNREACHABLE" for e in result.errors)
        assert any(e.code == "RDAP_TLS_NO_SERVICE_PORTS_REACHABLE" for e in result.errors)

    def test_one_port_unreachable_still_checks_other(self, base_config: Rdap92Config) -> None:
        """When one port fails but the other succeeds, we get an error
        for the unreachable port but no consistency error (only 1 response)."""
        import requests as _req

        class PartialQuerier(RdapServicePortQuerier):
            def query(
                self, *, base_url: str, service_port: ServicePort, path: str
            ) -> dict[str, Any]:
                if service_port.ip == IPV6_PORT.ip:
                    raise _req.ConnectionError("IPv6 unreachable")
                return copy.deepcopy(SAMPLE_DOMAIN_RESPONSE)

        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=PartialQuerier()
        )
        result = checker.run()
        assert not result.passed
        unreachable = [e for e in result.errors if e.code == "RDAP_TLS_SERVICE_PORT_UNREACHABLE"]
        assert len(unreachable) >= 1
        assert IPV6_PORT.ip in unreachable[0].detail

    def test_non_200_status_produces_query_failed(self, base_config: Rdap92Config) -> None:
        class Non200Querier(RdapServicePortQuerier):
            def query(
                self, *, base_url: str, service_port: ServicePort, path: str
            ) -> dict[str, Any]:
                raise RdapConformanceError(f"status 503 for {path}")

        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver(TWO_PORTS), querier=Non200Querier()
        )
        result = checker.run()
        assert not result.passed
        assert any(e.code == "RDAP_QUERY_FAILED" for e in result.errors)


# ===================================================================
# Multiple TLD / base URL tests
# ===================================================================


class TestMultipleTLDs:
    def test_checks_multiple_tlds_independently(self) -> None:
        config = Rdap92Config(
            base_urls=[
                {"tld": "alpha", "baseURL": "https://rdap.alpha.test/"},
                {"tld": "beta", "baseURL": "https://rdap.beta.test/"},
            ],
            test_domains=[
                {"tld": "alpha", "name": "test.alpha"},
                {"tld": "beta", "name": "test.beta"},
            ],
            test_entities=[
                {"tld": "alpha", "handle": "1001"},
                {"tld": "beta", "handle": "2002"},
            ],
            test_nameservers=[
                {"tld": "alpha", "nameserver": "ns1.alpha.com"},
                {"tld": "beta", "nameserver": "ns1.beta.com"},
            ],
        )
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            config, resolver=StubResolver(TWO_PORTS), querier=querier
        )
        result = checker.run()
        assert result.passed

        all_paths = {call[2] for call in querier.calls}
        assert "domain/test.alpha" in all_paths
        assert "domain/test.beta" in all_paths
        assert "entity/1001" in all_paths
        assert "entity/2002" in all_paths
        assert "nameserver/ns1.alpha.com" in all_paths
        assert "nameserver/ns1.beta.com" in all_paths


# ===================================================================
# Rdap92Result tests
# ===================================================================


class TestRdap92Result:
    def test_initially_passes(self) -> None:
        result = Rdap92Result()
        assert result.passed
        assert result.errors == []

    def test_add_error_sets_passed_false_for_error_severity(self) -> None:
        result = Rdap92Result()
        result.add_error("RDAP_QUERY_FAILED", "ERROR", "query failed")
        assert not result.passed
        assert len(result.errors) == 1

    def test_add_error_sets_passed_false_for_critical_severity(self) -> None:
        result = Rdap92Result()
        result.add_error("RDAP_TLS_NO_SERVICE_PORTS_REACHABLE", "CRITICAL", "no ports")
        assert not result.passed

    def test_add_error_preserves_passed_for_warning(self) -> None:
        result = Rdap92Result()
        result.add_error("SOME_WARNING", "WARNING", "just a warning")
        assert result.passed
        assert len(result.errors) == 1


# ===================================================================
# ServicePort dataclass tests
# ===================================================================


class TestServicePort:
    def test_frozen_dataclass(self) -> None:
        sp = ServicePort(ip="1.2.3.4", port=443, family=socket.AF_INET)
        assert sp.ip == "1.2.3.4"
        assert sp.port == 443
        with pytest.raises(AttributeError):
            sp.ip = "5.6.7.8"  # type: ignore[misc]

    def test_equality(self) -> None:
        sp1 = ServicePort(ip="1.2.3.4", port=443, family=socket.AF_INET)
        sp2 = ServicePort(ip="1.2.3.4", port=443, family=socket.AF_INET)
        assert sp1 == sp2


# ===================================================================
# Single service port edge case
# ===================================================================


class TestSinglePort:
    def test_single_port_skips_consistency_check(self, base_config: Rdap92Config) -> None:
        querier = StubQuerier()
        querier.set_default(SAMPLE_DOMAIN_RESPONSE)
        checker = ServicePortConsistencyChecker(
            base_config, resolver=StubResolver([IPV4_PORT]), querier=querier
        )
        result = checker.run()
        assert result.passed
        assert not result.errors


# ===================================================================
# Rdap92Error dataclass tests
# ===================================================================


class TestRdap92Error:
    def test_frozen_attributes(self) -> None:
        err = Rdap92Error(code="RDAP_QUERY_FAILED", severity="ERROR", detail="oops")
        assert err.code == "RDAP_QUERY_FAILED"
        assert err.severity == "ERROR"
        assert err.detail == "oops"
        with pytest.raises(AttributeError):
            err.code = "OTHER"  # type: ignore[misc]
