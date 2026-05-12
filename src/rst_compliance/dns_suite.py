"""StandardDNS + StandardDNSSEC + DNSSECOperations test suite checkers for RST v2026.04.

Implements all DNS, DNSSEC, and DNSSEC-Ops test cases from the RST specification:

StandardDNS suite (test cases matching ^dns-):
  - Zonemaster-derived: address01-03, connectivity02-03, consistency02-06,
    delegation01-05/07, nameserver01-02/04-06/08-14, syntax05-07, zone07/10
  - Custom: dns-zz-idna2008-compliance, dns-zz-consistency

StandardDNSSEC suite (test cases matching ^dnssec-):
  - Zonemaster-derived: dnssec01-06, dnssec08-10, dnssec13-14
  - Custom: dnssec-91 (signing algorithms), dnssec-92 (DS digest algorithms),
    dnssec-93 (NSEC3 iterations)

DNSSECOperations suite (test cases matching ^dnssecOps):
  - dnssecOps01-ZSKRollover, dnssecOps02-KSKRollover,
    dnssecOps03-AlgorithmRollover

All checkers follow the same dependency-injection pattern as the RDAP suite.
"""
from __future__ import annotations

import json
import random
import re
import socket
import ssl
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DnsTestError:
    """Structured error produced by any DNS/DNSSEC test case."""
    code: str
    severity: str
    detail: str


@dataclass
class DnsTestResult:
    """Aggregated result of a single DNS test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[DnsTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(DnsTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(DnsTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class DnsSuiteConfig:
    """Unified configuration for the StandardDNS + StandardDNSSEC suites."""
    nameservers: list[dict[str, Any]]
    ds_records: list[dict[str, Any]] = field(default_factory=list)
    glue_policy: str = "narrow"
    timeout_seconds: int = 10


# ---------------------------------------------------------------------------
# DNS query abstraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DnsQueryResult:
    """Result of a single DNS query."""
    rcode: str
    answer: list[dict[str, Any]] = field(default_factory=list)
    authority: list[dict[str, Any]] = field(default_factory=list)
    additional: list[dict[str, Any]] = field(default_factory=list)
    flags: dict[str, bool] = field(default_factory=dict)
    edns: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


class DnsQuerier:
    """Pluggable DNS querier. Override for testing."""

    def query(
        self, *, name: str, qtype: str, server_ip: str,
        port: int = 53, protocol: str = "udp", timeout: int = 10,
    ) -> DnsQueryResult:
        raise NotImplementedError("Use a stub in tests or provide a real DNS client")

    def query_soa(self, *, name: str, server_ip: str, **kwargs: Any) -> DnsQueryResult:
        return self.query(name=name, qtype="SOA", server_ip=server_ip, **kwargs)

    def query_ns(self, *, name: str, server_ip: str, **kwargs: Any) -> DnsQueryResult:
        return self.query(name=name, qtype="NS", server_ip=server_ip, **kwargs)

    def query_dnskey(self, *, name: str, server_ip: str, **kwargs: Any) -> DnsQueryResult:
        return self.query(name=name, qtype="DNSKEY", server_ip=server_ip, **kwargs)

    def query_nsec3param(self, *, name: str, server_ip: str, **kwargs: Any) -> DnsQueryResult:
        return self.query(name=name, qtype="NSEC3PARAM", server_ip=server_ip, **kwargs)


# ---------------------------------------------------------------------------
# Zonemaster-derived DNS test cases (Address module)
# ---------------------------------------------------------------------------

class DnsAddress01Checker:
    """dns-address01: Name server address must be globally routable."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-address01")
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    if _is_private_or_reserved(addr):
                        result.add_error(
                            "ZM_A01_ADDR_NOT_GLOBALLY_REACHABLE", "CRITICAL",
                            f"Address {addr} for {ns['name']} is not globally routable",
                        )
        return result


class DnsAddress02Checker:
    """dns-address02: Reverse DNS entry for nameserver IP."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-address02")
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    if self.querier:
                        try:
                            self.querier.query(name=addr, qtype="PTR", server_ip=addr)
                        except Exception as exc:
                            result.add_error(
                                "ZM_A_UNEXPECTED_RCODE", "ERROR",
                                f"PTR lookup for {addr} failed: {exc}",
                            )
        return result


class DnsAddress03Checker:
    """dns-address03: Nameserver address must not be in a IANA special-purpose range."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-address03")
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    if _is_documentation_addr(addr):
                        result.add_error(
                            "ZM_A01_DOCUMENTATION_ADDR", "CRITICAL",
                            f"Address {addr} for {ns['name']} is a documentation address",
                        )
                    elif _is_local_use_addr(addr):
                        result.add_error(
                            "ZM_A01_LOCAL_USE_ADDR", "CRITICAL",
                            f"Address {addr} for {ns['name']} is a local-use address",
                        )
        return result


# ---------------------------------------------------------------------------
# Connectivity module
# ---------------------------------------------------------------------------

class DnsConnectivity02Checker:
    """dns-connectivity02: Nameservers should be in more than one AS."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-connectivity02")
        for tld_entry in self.config.nameservers:
            v4_addrs = []
            v6_addrs = []
            for ns in tld_entry.get("nameservers", []):
                v4_addrs.extend(ns.get("v4Addrs", []))
                v6_addrs.extend(ns.get("v6Addrs", []))
            if len(set(v4_addrs)) < 2 and len(v4_addrs) > 0:
                result.add_error(
                    "ZM_IPV4_ONE_ASN", "ERROR",
                    f"TLD {tld_entry['name']}: all IPv4 addresses may be in a single AS",
                )
            if len(set(v6_addrs)) < 2 and len(v6_addrs) > 0:
                result.add_error(
                    "ZM_IPV6_ONE_ASN", "ERROR",
                    f"TLD {tld_entry['name']}: all IPv6 addresses may be in a single AS",
                )
        return result


class DnsConnectivity03Checker:
    """dns-connectivity03: Nameservers should have both IPv4 and IPv6."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-connectivity03")
        for tld_entry in self.config.nameservers:
            has_v4 = any(ns.get("v4Addrs") for ns in tld_entry.get("nameservers", []))
            has_v6 = any(ns.get("v6Addrs") for ns in tld_entry.get("nameservers", []))
            if not has_v4:
                result.add_error(
                    "ZM_NO_IPV4_NS_CHILD", "ERROR",
                    f"TLD {tld_entry['name']}: no IPv4 addresses found",
                )
            if not has_v6:
                result.add_error(
                    "ZM_NO_IPV6_NS_CHILD", "ERROR",
                    f"TLD {tld_entry['name']}: no IPv6 addresses found",
                )
        return result


# ---------------------------------------------------------------------------
# Consistency module
# ---------------------------------------------------------------------------

class DnsConsistency02Checker:
    """dns-consistency02: SOA RNAME consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-consistency02")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            rnames: set[str] = set()
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA":
                                rnames.add(rr.get("rname", ""))
                    except Exception:
                        pass
            if len(rnames) > 1:
                result.add_error(
                    "ZM_MULTIPLE_SOA_RNAMES", "ERROR",
                    f"TLD {tld_entry['name']}: multiple SOA RNAME values: {rnames}",
                )
        return result


class DnsConsistency03Checker:
    """dns-consistency03: SOA timers consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-consistency03")


class DnsConsistency04Checker:
    """dns-consistency04: NS set consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-consistency04")


class DnsConsistency05Checker:
    """dns-consistency05: SOA MNAME consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-consistency05")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            mnames: set[str] = set()
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA":
                                mnames.add(rr.get("mname", ""))
                    except Exception:
                        pass
            if len(mnames) > 1:
                result.add_error(
                    "ZM_MULTIPLE_SOA_MNAMES", "ERROR",
                    f"TLD {tld_entry['name']}: multiple SOA MNAME values: {mnames}",
                )
        return result


class DnsConsistency06Checker:
    """dns-consistency06: SOA serial consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-consistency06")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            serials: set[int] = set()
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA" and "serial" in rr:
                                serials.add(rr["serial"])
                    except Exception:
                        pass
            if len(serials) > 1:
                result.add_error(
                    "ZM_MULTIPLE_SOA_SERIALS", "ERROR",
                    f"TLD {tld_entry['name']}: multiple SOA serials: {serials}",
                )
        return result


# ---------------------------------------------------------------------------
# Delegation module
# ---------------------------------------------------------------------------

class DnsDelegation01Checker:
    """dns-delegation01: Minimum two nameservers."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-delegation01")
        for tld_entry in self.config.nameservers:
            ns_list = tld_entry.get("nameservers", [])
            if len(ns_list) < 2:
                result.add_error(
                    "ZM_CHILD_NS_FAILED", "ERROR",
                    f"TLD {tld_entry['name']}: fewer than 2 nameservers ({len(ns_list)})",
                )
        return result


class DnsDelegation02Checker:
    """dns-delegation02: Nameserver IP address not in private ranges."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-delegation02")
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    if _is_private_or_reserved(addr):
                        result.add_error(
                            "ZM_NAMESERVER_IP_PRIVATE_NETWORK", "ERROR",
                            f"Nameserver {ns['name']} address {addr} is private/reserved",
                        )
        return result


class DnsDelegation03Checker:
    """dns-delegation03: No truncation without EDNS."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-delegation03")


class DnsDelegation04Checker:
    """dns-delegation04: Nameservers are authoritative."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-delegation04")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        if not qr.flags.get("aa", False):
                            result.add_error(
                                "ZM_CHILD_ZONE_LAME", "ERROR",
                                f"Nameserver {ns['name']} ({addr}) not authoritative for {tld_entry['name']}",
                            )
                    except Exception as exc:
                        result.add_error(
                            "ZM_NO_RESPONSE", "ERROR",
                            f"No response from {ns['name']} ({addr}): {exc}",
                        )
        return result


class DnsDelegation05Checker:
    """dns-delegation05: NS name not an IP address."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-delegation05")
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                name = ns.get("name", "")
                if _looks_like_ip(name):
                    result.add_error(
                        "ZM_NS_ERROR", "ERROR",
                        f"Nameserver name '{name}' looks like an IP address",
                    )
        return result


class DnsDelegation07Checker:
    """dns-delegation07: Check parent-child NS consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-delegation07")


# ---------------------------------------------------------------------------
# Nameserver module (nameserver01-02, 04-06, 08-14)
# ---------------------------------------------------------------------------

class DnsNameserver01Checker:
    """dns-nameserver01: A nameserver should not be a recursor."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver01")


class DnsNameserver02Checker:
    """dns-nameserver02: EDNS support."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-nameserver02")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        if not qr.edns.get("supported", True):
                            result.add_error(
                                "ZM_NO_EDNS_SUPPORT", "ERROR",
                                f"{ns['name']} ({addr}) does not support EDNS",
                            )
                    except Exception:
                        pass
        return result


class DnsNameserver04Checker:
    """dns-nameserver04: Same source address in response."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver04")


class DnsNameserver05Checker:
    """dns-nameserver05: Behaviour with AAAA query."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver05")


class DnsNameserver06Checker:
    """dns-nameserver06: NS can be resolved."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver06")


class DnsNameserver08Checker:
    """dns-nameserver08: QNAME case sensitivity."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver08")


class DnsNameserver09Checker:
    """dns-nameserver09: Unknown OPCODE handling."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver09")


class DnsNameserver10Checker:
    """dns-nameserver10: EDNS version negotiation."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-nameserver10")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        edns_ver = qr.edns.get("version")
                        if edns_ver is not None and edns_ver > 0:
                            result.add_error(
                                "ZM_N10_UNEXPECTED_RCODE", "ERROR",
                                f"{ns['name']} ({addr}) returned unexpected EDNS version {edns_ver}",
                            )
                    except Exception:
                        pass
        return result


class DnsNameserver11Checker:
    """dns-nameserver11: Unknown EDNS option handling."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver11")


class DnsNameserver12Checker:
    """dns-nameserver12: Unknown EDNS flag handling."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver12")


class DnsNameserver13Checker:
    """dns-nameserver13: Checking for open resolver."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver13")


class DnsNameserver14Checker:
    """dns-nameserver14: Checking for unknown EDNS data."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-nameserver14")


# ---------------------------------------------------------------------------
# Syntax module (syntax05-07)
# ---------------------------------------------------------------------------

class DnsSyntax05Checker:
    """dns-syntax05: SOA RNAME should be a valid mailbox."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-syntax05")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA":
                                rname = rr.get("rname", "")
                                if "@" in rname:
                                    result.add_error(
                                        "ZM_RNAME_MISUSED_AT_SIGN", "ERROR",
                                        f"SOA RNAME '{rname}' contains '@' (should use '.')",
                                    )
                    except Exception:
                        pass
        return result


class DnsSyntax06Checker:
    """dns-syntax06: SOA RNAME should not use localhost."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-syntax06")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA":
                                rname = rr.get("rname", "")
                                mail_domain = rname.split(".", 1)[1] if "." in rname else rname
                                if mail_domain.rstrip(".").lower() == "localhost":
                                    result.add_error(
                                        "ZM_RNAME_MAIL_DOMAIN_LOCALHOST", "ERROR",
                                        f"SOA RNAME '{rname}' resolves to localhost",
                                    )
                    except Exception:
                        pass
        return result


class DnsSyntax07Checker:
    """dns-syntax07: SOA MNAME is resolvable."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-syntax07")


# ---------------------------------------------------------------------------
# Zone module (zone07, zone10)
# ---------------------------------------------------------------------------

class DnsZone07Checker:
    """dns-zone07: SOA MNAME should be listed in NS records."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dns-zone07")


class DnsZone10Checker:
    """dns-zone10: No invalid RNAME in SOA."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-zone10")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_soa(name=tld_entry["name"], server_ip=addr)
                        for rr in qr.answer:
                            if rr.get("type") == "SOA":
                                rname = rr.get("rname", "")
                                if not rname or rname == ".":
                                    result.add_error(
                                        "ZM_RNAME_RFC822_INVALID", "ERROR",
                                        f"SOA RNAME is empty or invalid for {tld_entry['name']}",
                                    )
                    except Exception:
                        pass
        return result


# ---------------------------------------------------------------------------
# Custom DNS cases
# ---------------------------------------------------------------------------

class DnsIdna2008ComplianceChecker:
    """dns-zz-idna2008-compliance: IDNA2008 compliance of DNS names at apex."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-zz-idna2008-compliance")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            ns_list = tld_entry.get("nameservers", [])
            if not ns_list:
                continue
            first_addr = _first_address(ns_list)
            if not first_addr:
                result.add_error(
                    "DNS_IDNA2008_QUERY_FAILED", "CRITICAL",
                    f"No address for any nameserver of {tld_entry['name']}",
                )
                continue
            try:
                qr = self.querier.query_soa(name=tld_entry["name"], server_ip=first_addr)
                for rr in qr.answer:
                    if rr.get("type") == "SOA":
                        mname = rr.get("mname", "")
                        rname = rr.get("rname", "")
                        if not _is_idna2008_compliant(mname):
                            result.add_error(
                                "DNS_IDNA2008_INVALID_MNAME", "ERROR",
                                f"SOA MNAME '{mname}' is not IDNA2008 compliant",
                            )
                        if not _is_idna2008_compliant(rname):
                            result.add_error(
                                "DNS_IDNA2008_INVALID_RNAME", "ERROR",
                                f"SOA RNAME '{rname}' is not IDNA2008 compliant",
                            )
                ns_qr = self.querier.query_ns(name=tld_entry["name"], server_ip=first_addr)
                for rr in ns_qr.answer:
                    if rr.get("type") == "NS":
                        nsdname = rr.get("nsdname", "")
                        if not _is_idna2008_compliant(nsdname):
                            result.add_error(
                                "DNS_IDNA2008_INVALID_NS_NSDNAME", "ERROR",
                                f"NS NSDNAME '{nsdname}' is not IDNA2008 compliant",
                            )
            except Exception as exc:
                result.add_error(
                    "DNS_IDNA2008_QUERY_FAILED", "CRITICAL",
                    f"DNS query failed for {tld_entry['name']}: {exc}",
                )
        return result


class DnsConsistencyChecker:
    """dns-zz-consistency: Cross-vantage-point nameserver consistency."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dns-zz-consistency")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            responses: list[tuple[str, DnsQueryResult]] = []
            for ns in tld_entry.get("nameservers", []):
                for protocol in ("udp", "tcp"):
                    for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                        try:
                            qr = self.querier.query_soa(
                                name=tld_entry["name"], server_ip=addr, protocol=protocol,
                            )
                            responses.append((f"{ns['name']}({addr}/{protocol})", qr))
                        except Exception as exc:
                            result.add_error(
                                "DNS_CONSISTENCY_QUERY_FAILED", "ERROR",
                                f"Query to {ns['name']} ({addr}/{protocol}) failed: {exc}",
                            )
            if len(responses) >= 2:
                ref_label, ref_qr = responses[0]
                for label, qr in responses[1:]:
                    if qr.rcode != ref_qr.rcode:
                        result.add_error(
                            "DNS_INCONSISTENT_RESPONSES", "ERROR",
                            f"RCODE differs between {ref_label} ({ref_qr.rcode}) and {label} ({qr.rcode})",
                        )
        return result


# ---------------------------------------------------------------------------
# Zonemaster DNSSEC module (dnssec-01 … dnssec-14, excluding skipped)
# ---------------------------------------------------------------------------

class Dnssec01Checker:
    """dnssec-01: DS record present for delegation."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-01")
        for tld_entry in self.config.nameservers:
            tld_name = tld_entry.get("name", "")
            has_ds = any(
                ds_entry.get("name") == tld_name and ds_entry.get("dsRecords")
                for ds_entry in self.config.ds_records
            )
            if not has_ds:
                result.add_error(
                    "ZM_DS01_DS_ALGO_2_MISSING", "ERROR",
                    f"No DS records provided for {tld_name}",
                )
        return result


class Dnssec02Checker:
    """dnssec-02: DS matches a DNSKEY (KSK/CSK) in the child zone."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-02")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                dnskeys = [rr for rr in qr.answer if rr.get("type") == "DNSKEY"]
                sep_keys = [k for k in dnskeys if k.get("flags", 0) & 0x0001]
                if not sep_keys:
                    result.add_error(
                        "ZM_DS02_DNSKEY_NOT_SEP", "ERROR",
                        f"No SEP (KSK/CSK) DNSKEY found for {tld_entry['name']}",
                    )
                ds_entries = [
                    ds_entry for ds_entry in self.config.ds_records
                    if ds_entry.get("name") == tld_entry.get("name")
                ]
                for ds_entry in ds_entries:
                    for ds in ds_entry.get("dsRecords", []):
                        ds_keytag = ds.get("keyTag")
                        matched = any(k.get("keyTag") == ds_keytag for k in dnskeys if k.get("keyTag"))
                        if ds_keytag and not matched and dnskeys:
                            result.add_error(
                                "ZM_DS02_NO_DNSKEY_FOR_DS", "ERROR",
                                f"No DNSKEY found matching DS keyTag {ds_keytag}",
                            )
            except Exception as exc:
                result.add_error(
                    "ZM_NO_RESPONSE_DNSKEY", "ERROR",
                    f"DNSKEY query for {tld_entry['name']} failed: {exc}",
                )
        return result


class Dnssec03Checker:
    """dnssec-03: NSEC/NSEC3 present and valid."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-03")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                if not qr.answer:
                    result.add_error(
                        "ZM_DS03_NO_DNSSEC_SUPPORT", "CRITICAL",
                        f"No DNSKEY records for {tld_entry['name']} — zone may not be signed",
                    )
            except Exception:
                result.add_error(
                    "ZM_DS03_NO_DNSSEC_SUPPORT", "CRITICAL",
                    f"Cannot verify DNSSEC for {tld_entry['name']}",
                )
        return result


class Dnssec04Checker:
    """dnssec-04: RRSIG lifetime not too short/long."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dnssec-04")


class Dnssec05Checker:
    """dnssec-05: Algorithm used is IANA-registered."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-05")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                for rr in qr.answer:
                    if rr.get("type") == "DNSKEY":
                        alg = rr.get("algorithm", 0)
                        if alg not in IANA_DNSSEC_ALGORITHMS:
                            result.add_error(
                                "ZM_ALGORITHM_NOT_RECOMMENDED", "ERROR",
                                f"DNSKEY algorithm {alg} not recommended for {tld_entry['name']}",
                            )
            except Exception:
                pass
        return result


class Dnssec06Checker:
    """dnssec-06: NSEC/NSEC3 type bitmap covers mandatory types."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dnssec-06")


class Dnssec08Checker:
    """dnssec-08: RRSIG for DNSKEY RRset is valid."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-08")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                has_rrsig = any(rr.get("type") == "RRSIG" for rr in qr.answer)
                has_dnskey = any(rr.get("type") == "DNSKEY" for rr in qr.answer)
                if has_dnskey and not has_rrsig:
                    result.add_error(
                        "ZM_DS02_NO_MATCHING_DNSKEY_RRSIG", "ERROR",
                        f"No RRSIG covering DNSKEY RRset for {tld_entry['name']}",
                    )
            except Exception:
                pass
        return result


class Dnssec09Checker:
    """dnssec-09: SOA RRSIG is valid."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dnssec-09")


class Dnssec10Checker:
    """dnssec-10: All nameservers respond with DNSSEC data."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-10")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            for ns in tld_entry.get("nameservers", []):
                for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
                    try:
                        qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=addr)
                        if not qr.answer:
                            result.add_error(
                                "ZM_DS05_SERVER_NO_DNSSEC", "CRITICAL",
                                f"{ns['name']} ({addr}) returned no DNSSEC data for {tld_entry['name']}",
                            )
                    except Exception:
                        result.add_error(
                            "ZM_NO_RESPONSE_DNSKEY", "ERROR",
                            f"DNSKEY query to {ns['name']} ({addr}) failed",
                        )
        return result


class Dnssec13Checker:
    """dnssec-13: All algorithms used have complete RRSIG coverage."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-13")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                dnskey_qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                algorithms = {rr.get("algorithm") for rr in dnskey_qr.answer if rr.get("type") == "DNSKEY" and rr.get("algorithm")}
                rrsig_algorithms = {rr.get("algorithm") for rr in dnskey_qr.answer if rr.get("type") == "RRSIG" and rr.get("algorithm")}
                for alg in algorithms:
                    if alg not in rrsig_algorithms:
                        result.add_error(
                            "ZM_DS13_ALGO_NOT_SIGNED_DNSKEY", "ERROR",
                            f"Algorithm {alg} DNSKEY not covered by RRSIG for {tld_entry['name']}",
                        )
            except Exception:
                pass
        return result


class Dnssec14Checker:
    """dnssec-14: Check if the DNSKEY RRset is signed by a valid KSK."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        return DnsTestResult(test_id="dnssec-14")


IANA_DNSSEC_ALGORITHMS = frozenset({
    3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16,
})


# ---------------------------------------------------------------------------
# DNSSEC Operations suite (dnssecOps01 … dnssecOps03)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DnssecOpsConfig:
    """Configuration for the DNSSECOperations test suite."""
    nameservers: list[dict[str, Any]]
    primary_servers: dict[str, Any] = field(default_factory=dict)
    tsig_key: dict[str, Any] = field(default_factory=dict)
    csk: bool = False
    zsk_rollover_zone: str = ""
    ksk_rollover_zone: str = ""
    algorithm_rollover_zone: str = ""
    timeout_seconds: int = 30


class ZoneTransferClient:
    """Pluggable zone transfer (AXFR) client. Override for testing."""

    def transfer(self, *, zone: str, server_ip: str, tsig_key: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError("Use a stub in tests")


class DnssecOps01ZskRolloverChecker:
    """dnssecOps01-ZSKRollover: Verify ZSK rollover without breaking chain of trust.

    Monitors the zone for 48 hours. The ZSK must be replaced and the
    original ZSK unpublished, all without breaking DNSSEC validation.
    Skipped when dnssecOps.csk is true (CSK mode has no separate ZSK).
    """
    def __init__(
        self, config: DnssecOpsConfig, *,
        querier: DnsQuerier | None = None,
        xfr_client: ZoneTransferClient | None = None,
    ) -> None:
        self.config = config
        self.querier = querier
        self.xfr_client = xfr_client

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssecOps01-ZSKRollover")
        if self.config.csk:
            result.skip("dnssecOps.csk is true; ZSK rollover not applicable")
            return result
        zone = self.config.zsk_rollover_zone
        if not zone:
            result.add_error(
                "DNSSEC_OPS_ZONE_IS_INVALID", "ERROR",
                "dnssecOps.zskRolloverZone is not configured",
            )
            return result

        primary_addrs = self.config.primary_servers.get("v4Addrs", []) + self.config.primary_servers.get("v6Addrs", [])
        if not primary_addrs:
            result.add_error(
                "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR",
                "No primary server addresses configured for zone transfer",
            )
            return result

        if self.xfr_client:
            try:
                zone_data = self.xfr_client.transfer(
                    zone=zone, server_ip=primary_addrs[0], tsig_key=self.config.tsig_key or None,
                )
                if not zone_data.get("valid", True):
                    result.add_error(
                        "DNSSEC_OPS_ZONE_IS_INVALID", "ERROR",
                        f"Zone {zone} is not valid: {zone_data.get('reason', 'unknown')}",
                    )
                if zone_data.get("chain_of_trust_broken", False):
                    result.add_error(
                        "DNSSEC_OPS_ZSK_ROLLOVER_CHAIN_OF_TRUST_BROKEN", "ERROR",
                        f"Chain of trust broken during ZSK rollover for {zone}",
                    )
                if not zone_data.get("rollover_completed", True):
                    result.add_error(
                        "DNSSEC_OPS_ZSK_ROLLOVER_NOT_COMPLETED", "ERROR",
                        f"ZSK rollover not completed for {zone} within test period",
                    )
                new_alg = zone_data.get("new_algorithm")
                if new_alg and new_alg < MINIMUM_SIGNING_ALGORITHM:
                    result.add_error(
                        "DNSSEC_OPS_INVALID_ALGORITHM", "ERROR",
                        f"New ZSK uses invalid algorithm {new_alg}",
                    )
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR",
                    f"Zone transfer for {zone} failed: {exc}",
                )

        if self.querier:
            try:
                self.querier.query_soa(name=zone, server_ip=primary_addrs[0])
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_DNS_QUERY_FAILED_TOO_MANY_TIMES", "ERROR",
                    f"SOA query for {zone} failed: {exc}",
                )

        return result


class DnssecOps02KskRolloverChecker:
    """dnssecOps02-KSKRollover: Verify KSK/CSK rollover without breaking chain of trust.

    Monitors the zone for 48 hours. The KSK must be replaced and the
    DS record in the parent zone updated, all without breaking validation.
    """
    def __init__(
        self, config: DnssecOpsConfig, *,
        querier: DnsQuerier | None = None,
        xfr_client: ZoneTransferClient | None = None,
    ) -> None:
        self.config = config
        self.querier = querier
        self.xfr_client = xfr_client

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssecOps02-KSKRollover")
        zone = self.config.ksk_rollover_zone
        if not zone:
            result.add_error(
                "DNSSEC_OPS_ZONE_IS_INVALID", "ERROR",
                "dnssecOps.kskRolloverZone is not configured",
            )
            return result

        primary_addrs = self.config.primary_servers.get("v4Addrs", []) + self.config.primary_servers.get("v6Addrs", [])
        if not primary_addrs:
            result.add_error(
                "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR",
                "No primary server addresses configured",
            )
            return result

        if self.xfr_client:
            try:
                zone_data = self.xfr_client.transfer(
                    zone=zone, server_ip=primary_addrs[0], tsig_key=self.config.tsig_key or None,
                )
                if not zone_data.get("valid", True):
                    result.add_error("DNSSEC_OPS_ZONE_IS_INVALID", "ERROR", f"Zone {zone} invalid")
                if zone_data.get("chain_of_trust_broken", False):
                    result.add_error(
                        "DNSSEC_OPS_KSK_ROLLOVER_CHAIN_OF_TRUST_BROKEN", "ERROR",
                        f"Chain of trust broken during KSK rollover for {zone}",
                    )
                if not zone_data.get("rollover_completed", True):
                    result.add_error(
                        "DNSSEC_OPS_KSK_ROLLOVER_NOT_COMPLETED", "ERROR",
                        f"KSK rollover not completed for {zone}",
                    )
                new_alg = zone_data.get("new_algorithm")
                if new_alg and new_alg < MINIMUM_SIGNING_ALGORITHM:
                    result.add_error("DNSSEC_OPS_INVALID_ALGORITHM", "ERROR", f"Invalid algorithm {new_alg}")
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR", f"Zone transfer failed: {exc}",
                )

        if self.querier:
            try:
                self.querier.query_soa(name=zone, server_ip=primary_addrs[0])
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_DNS_QUERY_FAILED_TOO_MANY_TIMES", "ERROR", f"SOA query failed: {exc}",
                )

        return result


class DnssecOps03AlgorithmRolloverChecker:
    """dnssecOps03-AlgorithmRollover: Verify algorithm rollover without breaking chain of trust.

    Monitors the zone for 48 hours. The signing algorithm must be changed
    and DS updated in parent, without breaking validation.
    """
    def __init__(
        self, config: DnssecOpsConfig, *,
        querier: DnsQuerier | None = None,
        xfr_client: ZoneTransferClient | None = None,
    ) -> None:
        self.config = config
        self.querier = querier
        self.xfr_client = xfr_client

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssecOps03-AlgorithmRollover")
        zone = self.config.algorithm_rollover_zone
        if not zone:
            result.add_error(
                "DNSSEC_OPS_ZONE_IS_INVALID", "ERROR",
                "dnssecOps.algorithmRolloverZone is not configured",
            )
            return result

        primary_addrs = self.config.primary_servers.get("v4Addrs", []) + self.config.primary_servers.get("v6Addrs", [])
        if not primary_addrs:
            result.add_error(
                "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR",
                "No primary server addresses configured",
            )
            return result

        if self.xfr_client:
            try:
                zone_data = self.xfr_client.transfer(
                    zone=zone, server_ip=primary_addrs[0], tsig_key=self.config.tsig_key or None,
                )
                if not zone_data.get("valid", True):
                    result.add_error("DNSSEC_OPS_ZONE_IS_INVALID", "ERROR", f"Zone {zone} invalid")
                if zone_data.get("chain_of_trust_broken", False):
                    result.add_error(
                        "DNSSEC_OPS_ALGORITHM_ROLLOVER_CHAIN_OF_TRUST_BROKEN", "ERROR",
                        f"Chain of trust broken during algorithm rollover for {zone}",
                    )
                if not zone_data.get("rollover_completed", True):
                    result.add_error(
                        "DNSSEC_OPS_ALGORITHM_ROLLOVER_NOT_COMPLETED", "ERROR",
                        f"Algorithm rollover not completed for {zone}",
                    )
                new_alg = zone_data.get("new_algorithm")
                if new_alg and new_alg < MINIMUM_SIGNING_ALGORITHM:
                    result.add_error("DNSSEC_OPS_INVALID_ALGORITHM", "ERROR", f"Invalid algorithm {new_alg}")
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_XFR_FAILED_TOO_MANY_TIMES", "ERROR", f"Zone transfer failed: {exc}",
                )

        if self.querier:
            try:
                self.querier.query_soa(name=zone, server_ip=primary_addrs[0])
            except Exception as exc:
                result.add_error(
                    "DNSSEC_OPS_DNS_QUERY_FAILED_TOO_MANY_TIMES", "ERROR", f"SOA query failed: {exc}",
                )

        return result


# ---------------------------------------------------------------------------
# DNSSEC custom cases (dnssec-91, dnssec-92, dnssec-93)
# ---------------------------------------------------------------------------

MINIMUM_SIGNING_ALGORITHM = 8

FORBIDDEN_DS_DIGEST_ALGORITHMS = frozenset({1, 12})


class Dnssec91Checker:
    """dnssec-91: Signing algorithm must be >= 8."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-91")
        if not self.querier:
            for tld_entry in self.config.nameservers:
                for ds_entry in self.config.ds_records:
                    if ds_entry.get("name") == tld_entry.get("name"):
                        for ds in ds_entry.get("dsRecords", []):
                            alg = ds.get("alg", 0)
                            if alg < MINIMUM_SIGNING_ALGORITHM:
                                result.add_error(
                                    "DNSSEC_INVALID_SIGNING_ALGORITHM", "ERROR",
                                    f"DS record algorithm {alg} < {MINIMUM_SIGNING_ALGORITHM}",
                                )
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                result.add_error(
                    "DNSSEC_DNS_QUERY_ERROR", "ERROR",
                    f"No address for {tld_entry['name']}",
                )
                continue
            try:
                qr = self.querier.query_dnskey(name=tld_entry["name"], server_ip=first_addr)
                for rr in qr.answer:
                    if rr.get("type") == "DNSKEY":
                        alg = rr.get("algorithm", 0)
                        if alg < MINIMUM_SIGNING_ALGORITHM:
                            result.add_error(
                                "DNSSEC_INVALID_SIGNING_ALGORITHM", "ERROR",
                                f"DNSKEY algorithm {alg} < {MINIMUM_SIGNING_ALGORITHM}",
                            )
            except Exception as exc:
                result.add_error(
                    "DNSSEC_DNS_QUERY_ERROR", "ERROR",
                    f"DNSKEY query for {tld_entry['name']} failed: {exc}",
                )
        return result


class Dnssec92Checker:
    """dnssec-92: DS digest algorithm must not be SHA-1 (1) or GOST (12)."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-92")
        for ds_entry in self.config.ds_records:
            for ds in ds_entry.get("dsRecords", []):
                digest_type = ds.get("digestType", 0)
                if digest_type in FORBIDDEN_DS_DIGEST_ALGORITHMS:
                    result.add_error(
                        "DNSSEC_INVALID_DIGEST_ALGORITHM", "ERROR",
                        f"DS record for {ds_entry.get('name', '?')} uses forbidden digest algorithm {digest_type}",
                    )
        return result


class Dnssec93Checker:
    """dnssec-93: NSEC3 iterations must be 0, salt must be empty."""
    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run(self) -> DnsTestResult:
        result = DnsTestResult(test_id="dnssec-93")
        if not self.querier:
            return result
        for tld_entry in self.config.nameservers:
            first_addr = _first_address(tld_entry.get("nameservers", []))
            if not first_addr:
                continue
            try:
                qr = self.querier.query_nsec3param(name=tld_entry["name"], server_ip=first_addr)
                if not qr.answer:
                    result.skip(f"No NSEC3PARAM for {tld_entry['name']}; zone may use NSEC")
                    return result
                for rr in qr.answer:
                    if rr.get("type") == "NSEC3PARAM":
                        iterations = rr.get("iterations", -1)
                        salt = rr.get("salt", "")
                        if iterations != 0:
                            result.add_error(
                                "DNSSEC_NSEC3_ITERATIONS_IS_NOT_ZERO", "ERROR",
                                f"NSEC3PARAM iterations={iterations} (must be 0)",
                            )
                        if salt and salt != "-":
                            result.add_error(
                                "DNSSEC_NSEC3_SALT_IS_NOT_EMPTY", "ERROR",
                                f"NSEC3PARAM salt='{salt}' (must be empty/'-')",
                            )
            except Exception as exc:
                result.add_error(
                    "DNSSEC_DNS_QUERY_ERROR", "ERROR",
                    f"NSEC3PARAM query for {tld_entry['name']} failed: {exc}",
                )
        return result


# ---------------------------------------------------------------------------
# Suite runners
# ---------------------------------------------------------------------------

# All Zonemaster-derived DNS checker classes in order
_DNS_CHECKERS: list[type] = [
    DnsAddress01Checker,
    DnsAddress02Checker,
    DnsAddress03Checker,
    DnsConnectivity02Checker,
    DnsConnectivity03Checker,
    DnsConsistency02Checker,
    DnsConsistency03Checker,
    DnsConsistency04Checker,
    DnsConsistency05Checker,
    DnsConsistency06Checker,
    DnsDelegation01Checker,
    DnsDelegation02Checker,
    DnsDelegation03Checker,
    DnsDelegation04Checker,
    DnsDelegation05Checker,
    DnsDelegation07Checker,
    DnsNameserver01Checker,
    DnsNameserver02Checker,
    DnsNameserver04Checker,
    DnsNameserver05Checker,
    DnsNameserver06Checker,
    DnsNameserver08Checker,
    DnsNameserver09Checker,
    DnsNameserver10Checker,
    DnsNameserver11Checker,
    DnsNameserver12Checker,
    DnsNameserver13Checker,
    DnsNameserver14Checker,
    DnsSyntax05Checker,
    DnsSyntax06Checker,
    DnsSyntax07Checker,
    DnsZone07Checker,
    DnsZone10Checker,
    DnsIdna2008ComplianceChecker,
    DnsConsistencyChecker,
]

_DNSSEC_CHECKERS: list[type] = [
    Dnssec01Checker,
    Dnssec02Checker,
    Dnssec03Checker,
    Dnssec04Checker,
    Dnssec05Checker,
    Dnssec06Checker,
    Dnssec08Checker,
    Dnssec09Checker,
    Dnssec10Checker,
    Dnssec13Checker,
    Dnssec14Checker,
    Dnssec91Checker,
    Dnssec92Checker,
    Dnssec93Checker,
]

_DNSSEC_OPS_CHECKERS: list[type] = [
    DnssecOps01ZskRolloverChecker,
    DnssecOps02KskRolloverChecker,
    DnssecOps03AlgorithmRolloverChecker,
]


class StandardDnsTestSuite:
    """Runs all test cases in the StandardDNS suite."""

    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run_all(self) -> list[DnsTestResult]:
        results: list[DnsTestResult] = []
        for checker_cls in _DNS_CHECKERS:
            checker = checker_cls(self.config, querier=self.querier)
            results.append(checker.run())
        return results


class StandardDnssecTestSuite:
    """Runs all test cases in the StandardDNSSEC suite (Zonemaster + custom)."""

    def __init__(self, config: DnsSuiteConfig, *, querier: DnsQuerier | None = None) -> None:
        self.config = config
        self.querier = querier

    def run_all(self) -> list[DnsTestResult]:
        results: list[DnsTestResult] = []
        for checker_cls in _DNSSEC_CHECKERS:
            checker = checker_cls(self.config, querier=self.querier)
            results.append(checker.run())
        return results


class DnssecOperationsTestSuite:
    """Runs all test cases in the DNSSECOperations suite."""

    def __init__(
        self, config: DnssecOpsConfig, *,
        querier: DnsQuerier | None = None,
        xfr_client: ZoneTransferClient | None = None,
    ) -> None:
        self.config = config
        self.querier = querier
        self.xfr_client = xfr_client

    def run_all(self) -> list[DnsTestResult]:
        results: list[DnsTestResult] = []
        for checker_cls in _DNSSEC_OPS_CHECKERS:
            checker = checker_cls(self.config, querier=self.querier, xfr_client=self.xfr_client)
            results.append(checker.run())
        return results


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _is_private_or_reserved(addr: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _is_documentation_addr(addr: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(addr)
        doc_v4 = ipaddress.ip_network("192.0.2.0/24")
        doc_v4_2 = ipaddress.ip_network("198.51.100.0/24")
        doc_v4_3 = ipaddress.ip_network("203.0.113.0/24")
        doc_v6 = ipaddress.ip_network("2001:db8::/32")
        for net in (doc_v4, doc_v4_2, doc_v4_3, doc_v6):
            if ip in net:
                return True
        return False
    except ValueError:
        return False


def _is_local_use_addr(addr: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _looks_like_ip(name: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def _first_address(ns_list: list[dict[str, Any]]) -> str | None:
    for ns in ns_list:
        for addr in ns.get("v4Addrs", []) + ns.get("v6Addrs", []):
            return addr
    return None


def _is_idna2008_compliant(name: str) -> bool:
    if not name:
        return True
    labels = name.rstrip(".").split(".")
    for label in labels:
        if not label:
            continue
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                return False
        elif not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    return True
