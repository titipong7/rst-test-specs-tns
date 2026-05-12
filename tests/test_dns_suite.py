"""Tests for the StandardDNS + StandardDNSSEC test suites.

Covers all DNS test cases: Zonemaster-derived (address, connectivity,
consistency, delegation, nameserver, syntax, zone modules) plus custom
cases (dns-zz-idna2008-compliance, dns-zz-consistency) and DNSSEC custom
cases (dnssec-91, dnssec-92, dnssec-93).
"""
from __future__ import annotations

from typing import Any

import pytest

from rst_compliance.dns_suite import (
    DnsAddress01Checker,
    DnsAddress02Checker,
    DnsAddress03Checker,
    DnsConnectivity02Checker,
    DnsConnectivity03Checker,
    DnsConsistency02Checker,
    DnsConsistency06Checker,
    DnsConsistencyChecker,
    DnsDelegation01Checker,
    DnsDelegation02Checker,
    DnsDelegation04Checker,
    DnsDelegation05Checker,
    DnsIdna2008ComplianceChecker,
    DnsNameserver02Checker,
    DnsNameserver10Checker,
    DnsQuerier,
    DnsQueryResult,
    DnsSuiteConfig,
    DnsSyntax05Checker,
    DnsSyntax06Checker,
    DnsTestResult,
    DnsZone10Checker,
    Dnssec91Checker,
    Dnssec92Checker,
    Dnssec93Checker,
    StandardDnsTestSuite,
    StandardDnssecTestSuite,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_config() -> DnsSuiteConfig:
    return DnsSuiteConfig(
        nameservers=[{
            "name": "example",
            "nameservers": [
                {"name": "ns1.example.com", "v4Addrs": ["93.184.216.34"], "v6Addrs": ["2001:500:8d::53"]},
                {"name": "ns2.example.net", "v4Addrs": ["93.184.216.35"], "v6Addrs": ["2001:500:8e::53"]},
            ],
        }],
        ds_records=[{
            "name": "example",
            "dsRecords": [{"keyTag": 12345, "alg": 13, "digestType": 2, "digest": "AABBCCDD"}],
        }],
    )


# ---------------------------------------------------------------------------
# Stub DNS querier
# ---------------------------------------------------------------------------

class StubQuerier(DnsQuerier):
    def __init__(self, soa_answer: list[dict[str, Any]] | None = None, **kwargs: Any) -> None:
        self._soa = soa_answer or [{"type": "SOA", "mname": "ns1.example.com.", "rname": "admin.example.com.", "serial": 2026050101}]
        self._ns = kwargs.get("ns_answer", [{"type": "NS", "nsdname": "ns1.example.com."}, {"type": "NS", "nsdname": "ns2.example.net."}])
        self._dnskey = kwargs.get("dnskey_answer", [{"type": "DNSKEY", "algorithm": 13, "flags": 257}])
        self._nsec3param = kwargs.get("nsec3param_answer", [])
        self._flags = kwargs.get("flags", {"aa": True})
        self._edns = kwargs.get("edns", {"supported": True, "version": 0})
        self.calls: list[dict[str, Any]] = []

    def query(self, *, name: str, qtype: str, server_ip: str, **kwargs: Any) -> DnsQueryResult:
        self.calls.append({"name": name, "qtype": qtype, "server_ip": server_ip, **kwargs})
        if qtype == "SOA":
            return DnsQueryResult(rcode="NOERROR", answer=self._soa, flags=self._flags, edns=self._edns)
        if qtype == "NS":
            return DnsQueryResult(rcode="NOERROR", answer=self._ns, flags=self._flags)
        if qtype == "DNSKEY":
            return DnsQueryResult(rcode="NOERROR", answer=self._dnskey, flags=self._flags)
        if qtype == "NSEC3PARAM":
            return DnsQueryResult(rcode="NOERROR", answer=self._nsec3param, flags=self._flags)
        return DnsQueryResult(rcode="NOERROR")


class FailQuerier(DnsQuerier):
    def query(self, **kwargs: Any) -> DnsQueryResult:
        raise ConnectionError("DNS query failed")


# ===================================================================
# Address module tests
# ===================================================================

class TestDnsAddress01:
    def test_globally_routable_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsAddress01Checker(base_config).run()
        assert result.passed
        assert result.test_id == "dns-address01"

    def test_private_address_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["192.168.1.1"]}],
        }])
        result = DnsAddress01Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_A01_ADDR_NOT_GLOBALLY_REACHABLE" for e in result.errors)

    def test_loopback_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["127.0.0.1"]}],
        }])
        result = DnsAddress01Checker(config).run()
        assert not result.passed


class TestDnsAddress03:
    def test_documentation_addr_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["192.0.2.1"]}],
        }])
        result = DnsAddress03Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_A01_DOCUMENTATION_ADDR" for e in result.errors)

    def test_loopback_as_local_use(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["127.0.0.1"]}],
        }])
        result = DnsAddress03Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_A01_LOCAL_USE_ADDR" for e in result.errors)


# ===================================================================
# Connectivity module tests
# ===================================================================

class TestDnsConnectivity02:
    def test_multiple_addresses_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsConnectivity02Checker(base_config).run()
        assert result.passed

    def test_single_ipv4_warns(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [
                {"name": "ns1.example.com", "v4Addrs": ["93.184.216.34"]},
                {"name": "ns2.example.net", "v4Addrs": ["93.184.216.34"]},
            ],
        }])
        result = DnsConnectivity02Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_IPV4_ONE_ASN" for e in result.errors)


class TestDnsConnectivity03:
    def test_both_families_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsConnectivity03Checker(base_config).run()
        assert result.passed

    def test_no_ipv6_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["93.184.216.34"]}],
        }])
        result = DnsConnectivity03Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_NO_IPV6_NS_CHILD" for e in result.errors)

    def test_no_ipv4_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v6Addrs": ["2001:500:8d::53"]}],
        }])
        result = DnsConnectivity03Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_NO_IPV4_NS_CHILD" for e in result.errors)


# ===================================================================
# Consistency module tests
# ===================================================================

class TestDnsConsistency06:
    def test_consistent_serials_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsConsistency06Checker(base_config, querier=querier).run()
        assert result.passed

    def test_multiple_serials_fails(self, base_config: DnsSuiteConfig) -> None:
        call_count = [0]
        class MultiSerialQuerier(DnsQuerier):
            def query(self, **kwargs: Any) -> DnsQueryResult:
                call_count[0] += 1
                serial = 2026050101 if call_count[0] <= 2 else 2026050102
                return DnsQueryResult(rcode="NOERROR", answer=[{"type": "SOA", "serial": serial}])

        result = DnsConsistency06Checker(base_config, querier=MultiSerialQuerier()).run()
        assert not result.passed
        assert any(e.code == "ZM_MULTIPLE_SOA_SERIALS" for e in result.errors)


# ===================================================================
# Delegation module tests
# ===================================================================

class TestDnsDelegation01:
    def test_two_nameservers_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsDelegation01Checker(base_config).run()
        assert result.passed

    def test_one_nameserver_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["93.184.216.34"]}],
        }])
        result = DnsDelegation01Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_CHILD_NS_FAILED" for e in result.errors)


class TestDnsDelegation02:
    def test_public_addresses_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsDelegation02Checker(base_config).run()
        assert result.passed

    def test_private_address_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "ns1.example.com", "v4Addrs": ["10.0.0.1"]}],
        }])
        result = DnsDelegation02Checker(config).run()
        assert not result.passed


class TestDnsDelegation04:
    def test_authoritative_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(flags={"aa": True})
        result = DnsDelegation04Checker(base_config, querier=querier).run()
        assert result.passed

    def test_not_authoritative_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(flags={"aa": False})
        result = DnsDelegation04Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "ZM_CHILD_ZONE_LAME" for e in result.errors)


class TestDnsDelegation05:
    def test_hostname_passes(self, base_config: DnsSuiteConfig) -> None:
        result = DnsDelegation05Checker(base_config).run()
        assert result.passed

    def test_ip_as_name_fails(self) -> None:
        config = DnsSuiteConfig(nameservers=[{
            "name": "example",
            "nameservers": [{"name": "192.0.2.1", "v4Addrs": ["93.184.216.34"]}],
        }])
        result = DnsDelegation05Checker(config).run()
        assert not result.passed
        assert any(e.code == "ZM_NS_ERROR" for e in result.errors)


# ===================================================================
# Nameserver module tests
# ===================================================================

class TestDnsNameserver02:
    def test_edns_supported_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(edns={"supported": True})
        result = DnsNameserver02Checker(base_config, querier=querier).run()
        assert result.passed

    def test_no_edns_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(edns={"supported": False})
        result = DnsNameserver02Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "ZM_NO_EDNS_SUPPORT" for e in result.errors)


# ===================================================================
# Syntax module tests
# ===================================================================

class TestDnsSyntax05:
    def test_valid_rname_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsSyntax05Checker(base_config, querier=querier).run()
        assert result.passed

    def test_at_sign_in_rname_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(soa_answer=[{"type": "SOA", "rname": "admin@example.com"}])
        result = DnsSyntax05Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "ZM_RNAME_MISUSED_AT_SIGN" for e in result.errors)


class TestDnsSyntax06:
    def test_normal_rname_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsSyntax06Checker(base_config, querier=querier).run()
        assert result.passed

    def test_localhost_rname_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(soa_answer=[{"type": "SOA", "rname": "admin.localhost."}])
        result = DnsSyntax06Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "ZM_RNAME_MAIL_DOMAIN_LOCALHOST" for e in result.errors)


# ===================================================================
# Zone module tests
# ===================================================================

class TestDnsZone10:
    def test_valid_rname_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsZone10Checker(base_config, querier=querier).run()
        assert result.passed

    def test_empty_rname_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(soa_answer=[{"type": "SOA", "rname": ""}])
        result = DnsZone10Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "ZM_RNAME_RFC822_INVALID" for e in result.errors)


# ===================================================================
# Custom DNS cases
# ===================================================================

class TestDnsIdna2008Compliance:
    def test_compliant_names_pass(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsIdna2008ComplianceChecker(base_config, querier=querier).run()
        assert result.passed

    def test_invalid_mname_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(soa_answer=[{"type": "SOA", "mname": "ns1.exa mple.com.", "rname": "admin.example.com."}])
        result = DnsIdna2008ComplianceChecker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "DNS_IDNA2008_INVALID_MNAME" for e in result.errors)

    def test_query_failure_produces_critical(self, base_config: DnsSuiteConfig) -> None:
        result = DnsIdna2008ComplianceChecker(base_config, querier=FailQuerier()).run()
        assert not result.passed
        assert any(e.code == "DNS_IDNA2008_QUERY_FAILED" for e in result.errors)


class TestDnsConsistency:
    def test_consistent_responses_pass(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        result = DnsConsistencyChecker(base_config, querier=querier).run()
        assert result.passed

    def test_inconsistent_rcode_fails(self, base_config: DnsSuiteConfig) -> None:
        call_count = [0]
        class InconsistentQuerier(DnsQuerier):
            def query(self, **kwargs: Any) -> DnsQueryResult:
                call_count[0] += 1
                rcode = "NOERROR" if call_count[0] <= 2 else "SERVFAIL"
                return DnsQueryResult(rcode=rcode, answer=[{"type": "SOA", "serial": 1}])

        result = DnsConsistencyChecker(base_config, querier=InconsistentQuerier()).run()
        assert not result.passed
        assert any(e.code == "DNS_INCONSISTENT_RESPONSES" for e in result.errors)

    def test_query_failure_logged(self, base_config: DnsSuiteConfig) -> None:
        result = DnsConsistencyChecker(base_config, querier=FailQuerier()).run()
        assert not result.passed
        assert any(e.code == "DNS_CONSISTENCY_QUERY_FAILED" for e in result.errors)


# ===================================================================
# DNSSEC custom cases
# ===================================================================

class TestDnssec91:
    def test_algorithm_13_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(dnskey_answer=[{"type": "DNSKEY", "algorithm": 13}])
        result = Dnssec91Checker(base_config, querier=querier).run()
        assert result.passed

    def test_algorithm_5_fails_via_ds(self) -> None:
        config = DnsSuiteConfig(
            nameservers=[{"name": "example", "nameservers": []}],
            ds_records=[{"name": "example", "dsRecords": [{"alg": 5}]}],
        )
        result = Dnssec91Checker(config).run()
        assert not result.passed
        assert any(e.code == "DNSSEC_INVALID_SIGNING_ALGORITHM" for e in result.errors)

    def test_algorithm_8_passes_via_ds(self) -> None:
        config = DnsSuiteConfig(
            nameservers=[{"name": "example", "nameservers": []}],
            ds_records=[{"name": "example", "dsRecords": [{"alg": 8}]}],
        )
        result = Dnssec91Checker(config).run()
        assert result.passed


class TestDnssec92:
    def test_sha256_passes(self, base_config: DnsSuiteConfig) -> None:
        result = Dnssec92Checker(base_config).run()
        assert result.passed

    def test_sha1_fails(self) -> None:
        config = DnsSuiteConfig(
            nameservers=[],
            ds_records=[{"name": "example", "dsRecords": [{"digestType": 1}]}],
        )
        result = Dnssec92Checker(config).run()
        assert not result.passed
        assert any(e.code == "DNSSEC_INVALID_DIGEST_ALGORITHM" for e in result.errors)

    def test_gost_fails(self) -> None:
        config = DnsSuiteConfig(
            nameservers=[],
            ds_records=[{"name": "example", "dsRecords": [{"digestType": 12}]}],
        )
        result = Dnssec92Checker(config).run()
        assert not result.passed


class TestDnssec93:
    def test_zero_iterations_empty_salt_passes(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(nsec3param_answer=[{"type": "NSEC3PARAM", "iterations": 0, "salt": "-"}])
        result = Dnssec93Checker(base_config, querier=querier).run()
        assert result.passed

    def test_nonzero_iterations_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(nsec3param_answer=[{"type": "NSEC3PARAM", "iterations": 10, "salt": "-"}])
        result = Dnssec93Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "DNSSEC_NSEC3_ITERATIONS_IS_NOT_ZERO" for e in result.errors)

    def test_nonempty_salt_fails(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(nsec3param_answer=[{"type": "NSEC3PARAM", "iterations": 0, "salt": "ABCD"}])
        result = Dnssec93Checker(base_config, querier=querier).run()
        assert not result.passed
        assert any(e.code == "DNSSEC_NSEC3_SALT_IS_NOT_EMPTY" for e in result.errors)

    def test_no_nsec3param_skips(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier(nsec3param_answer=[])
        result = Dnssec93Checker(base_config, querier=querier).run()
        assert result.skipped


# ===================================================================
# DnsTestResult tests
# ===================================================================

class TestDnsTestResult:
    def test_initially_passes(self) -> None:
        r = DnsTestResult(test_id="dns-address01")
        assert r.passed and not r.skipped

    def test_skip(self) -> None:
        r = DnsTestResult(test_id="dns-connectivity02")
        r.skip("not applicable")
        assert r.skipped

    def test_add_error_marks_failed(self) -> None:
        r = DnsTestResult(test_id="dns-address01")
        r.add_error("TEST_ERROR", "ERROR", "detail")
        assert not r.passed


# ===================================================================
# Suite runner tests
# ===================================================================

class TestStandardDnsTestSuite:
    def test_runs_all_35_dns_test_cases(self, base_config: DnsSuiteConfig) -> None:
        suite = StandardDnsTestSuite(base_config)
        results = suite.run_all()
        assert len(results) == 35
        test_ids = {r.test_id for r in results}
        assert "dns-address01" in test_ids
        assert "dns-zz-idna2008-compliance" in test_ids
        assert "dns-zz-consistency" in test_ids

    def test_all_pass_with_valid_config(self, base_config: DnsSuiteConfig) -> None:
        querier = StubQuerier()
        suite = StandardDnsTestSuite(base_config, querier=querier)
        results = suite.run_all()
        failing = [r for r in results if not r.passed and not r.skipped]
        assert not failing, f"Unexpected failures: {[(r.test_id, r.errors) for r in failing]}"


class TestStandardDnssecTestSuite:
    def test_runs_all_3_dnssec_custom_cases(self, base_config: DnsSuiteConfig) -> None:
        suite = StandardDnssecTestSuite(base_config)
        results = suite.run_all()
        assert len(results) == 3
        test_ids = {r.test_id for r in results}
        assert "dnssec-91" in test_ids
        assert "dnssec-92" in test_ids
        assert "dnssec-93" in test_ids
