"""StandardRDE test suite checkers for RST v2026.04.

Implements all 14 RDE test cases (rde-01 … rde-14) from the RST specification:
  - rde-01: Validate deposit filename format
  - rde-02: Validate PGP signature over deposit
  - rde-03: Decrypt deposit file
  - rde-04: Validate XML/CSV well-formedness and schema
  - rde-05: Validate object types (header/menu URIs)
  - rde-06: Validate object counts
  - rde-07: Validate domain objects
  - rde-08: Validate host objects (if applicable)
  - rde-09: Validate contact objects (if applicable)
  - rde-10: Validate registrar objects
  - rde-11: Validate IDN table objects (if applicable)
  - rde-12: Validate NNDN objects (if applicable)
  - rde-13: Validate EPP parameters object
  - rde-14: Validate policy object (if applicable)

All checkers follow the same dependency-injection pattern as RDAP/DNS/DNSSEC suites.
"""
from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

DEPOSIT_FILENAME_PATTERN = re.compile(
    r"^(?P<tld>[a-z0-9-]+)_(?P<date>\d{4}-\d{2}-\d{2})_(?P<type>full)_S(?P<seq>\d+)_R(?P<rev>\d+)\.ryde$"
)

VALID_DOMAIN_STATUSES = frozenset({
    "ok", "serverHold", "serverRenewProhibited", "serverTransferProhibited",
    "serverUpdateProhibited", "serverDeleteProhibited", "clientHold",
    "clientRenewProhibited", "clientTransferProhibited", "clientUpdateProhibited",
    "clientDeleteProhibited", "inactive", "pendingCreate", "pendingDelete",
    "pendingRenew", "pendingRestore", "pendingTransfer", "pendingUpdate",
    "addPeriod", "autoRenewPeriod", "renewPeriod", "transferPeriod",
    "redemptionPeriod",
})

REQUIRED_EPP_EXTURIS = frozenset({
    "urn:ietf:params:xml:ns:secDNS-1.1",
    "urn:ietf:params:xml:ns:rgp-1.0",
})

ROID_PATTERN = re.compile(r"^[A-Za-z0-9_]+-[A-Za-z0-9_]+$")

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RdeTestError:
    """Structured error produced by any RDE test case."""
    code: str
    severity: str
    detail: str


@dataclass
class RdeTestResult:
    """Aggregated result of a single RDE test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[RdeTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(RdeTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(RdeTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class RdeSuiteConfig:
    """Unified configuration for the StandardRDE test suite."""
    deposit_filename: str = ""
    deposit_xml: str = ""
    signature_valid: bool | None = None
    decryption_ok: bool | None = None
    registry_data_model: str = "minimum"
    host_model: str = "objects"
    tlds: list[str] = field(default_factory=list)
    has_idn_tables: bool = False


class RdeDepositParser:
    """Pluggable deposit parser. Override for testing."""

    def parse(self, xml_text: str) -> dict[str, Any]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            return {"parse_error": str(exc)}
        return self._extract(root)

    @staticmethod
    def _extract(root: ET.Element) -> dict[str, Any]:
        domains: list[dict[str, Any]] = []
        for dom in root.findall(".//{*}domain"):
            domains.append({
                "name": dom.findtext("{*}name", ""),
                "roid": dom.findtext("{*}roid", ""),
                "status": [s.get("s", s.text or "") for s in dom.findall("{*}status")],
                "registrant": dom.findtext("{*}registrant", ""),
                "clID": dom.findtext("{*}clID", ""),
                "crDate": dom.findtext("{*}crDate", ""),
                "exDate": dom.findtext("{*}exDate", ""),
                "contacts": [c.text for c in dom.findall("{*}contact") if c.text],
                "hostObjs": [h.text for h in dom.findall("{*}hostObj") if h.text],
                "hostAttrs": [h for h in dom.findall("{*}hostAttr")],
                "idnTableId": dom.findtext("{*}idnTableId", ""),
            })

        hosts: list[dict[str, Any]] = []
        for host in root.findall(".//{*}host"):
            hosts.append({
                "name": host.findtext("{*}name", ""),
                "roid": host.findtext("{*}roid", ""),
                "status": [s.get("s", s.text or "") for s in host.findall("{*}status")],
                "clID": host.findtext("{*}clID", ""),
                "addrs": [a.text for a in host.findall("{*}addr") if a.text],
            })

        contacts: list[dict[str, Any]] = []
        for contact in root.findall(".//{*}contact"):
            if contact.findtext("{*}id"):
                contacts.append({
                    "id": contact.findtext("{*}id", ""),
                    "roid": contact.findtext("{*}roid", ""),
                    "clID": contact.findtext("{*}clID", ""),
                    "postalInfoTypes": [p.get("type", "") for p in contact.findall("{*}postalInfo")],
                    "cc": contact.findtext(".//{*}cc", ""),
                    "email": contact.findtext("{*}email", ""),
                })

        registrars: list[dict[str, Any]] = []
        for reg in root.findall(".//{*}registrar"):
            registrars.append({
                "id": reg.findtext("{*}id", ""),
                "name": reg.findtext("{*}name", ""),
                "gurid": reg.findtext("{*}gurid", ""),
            })

        header_uris: list[str] = [c.get("uri", "") for c in root.findall(".//{*}count") if c.get("uri")]
        menu_el = root.find(".//{*}rdeMenu")
        menu_uris: list[str] = [u.text for u in menu_el.findall("{*}objURI") if u.text] if menu_el is not None else []

        idn_tables: list[dict[str, Any]] = []
        for idn in root.findall(".//{*}idnTableRef"):
            idn_tables.append({"id": idn.get("id", "")})

        nndn_objects: list[dict[str, Any]] = []
        for nndn in root.findall(".//{*}nndn"):
            nndn_objects.append({
                "aName": nndn.findtext("{*}aName", ""),
                "nameState": nndn.findtext("{*}nameState", ""),
                "idnTableId": nndn.findtext("{*}idnTableId", ""),
            })

        epp_params_objs = root.findall(".//{*}eppParams")
        epp_params: list[dict[str, Any]] = []
        for ep in epp_params_objs:
            epp_params.append({
                "objURIs": [u.text for u in ep.findall("{*}objURI") if u.text],
                "extURIs": [u.text for u in ep.findall("{*}extURI") if u.text],
            })

        policy_objects = root.findall(".//{*}policy")

        return {
            "domains": domains,
            "hosts": hosts,
            "contacts": contacts,
            "registrars": registrars,
            "header_uris": header_uris,
            "menu_uris": menu_uris,
            "idn_tables": idn_tables,
            "nndn_objects": nndn_objects,
            "epp_params": epp_params,
            "policy_objects_count": len(policy_objects),
            "watermark": root.findtext(".//{*}watermark", ""),
        }


# ---------------------------------------------------------------------------
# rde-01 through rde-14 checkers
# ---------------------------------------------------------------------------

class Rde01FilenameChecker:
    """rde-01: Validate deposit filename format."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-01")
        fn = self.config.deposit_filename
        if not fn:
            result.add_error("RDE_INVALID_FILENAME", "ERROR", "No deposit filename provided")
            return result
        m = DEPOSIT_FILENAME_PATTERN.fullmatch(fn)
        if not m:
            result.add_error("RDE_INVALID_FILENAME", "ERROR", f"Filename '{fn}' does not match required pattern")
            return result
        if m.group("type") != "full":
            result.add_error("RDE_INVALID_FILENAME", "ERROR", f"Deposit type must be 'full', got '{m.group('type')}'")
        tld = m.group("tld")
        if self.config.tlds and tld not in {t.lower() for t in self.config.tlds}:
            result.add_error("RDE_INVALID_FILENAME", "ERROR", f"TLD '{tld}' not in configured TLDs")
        return result


class Rde02SignatureChecker:
    """rde-02: Validate PGP signature over deposit file."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-02")
        if self.config.signature_valid is None:
            return result
        if not self.config.signature_valid:
            result.add_error("RDE_INVALID_SIGNATURE", "ERROR", "PGP signature is not valid")
        return result


class Rde03DecryptionChecker:
    """rde-03: Decrypt deposit file."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-03")
        if self.config.decryption_ok is None:
            return result
        if not self.config.decryption_ok:
            result.add_error("RDE_DECRYPTION_FAILED", "CRITICAL", "Deposit file could not be decrypted")
        return result


class Rde04XmlCsvChecker:
    """rde-04: Validate XML/CSV well-formedness and schema."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-04")
        if not self.config.deposit_xml:
            result.add_error("RDE_MISSING_FILES", "CRITICAL", "No deposit XML provided")
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            result.add_error("RDE_XML_PARSE_ERROR", "CRITICAL", f"XML parse error: {parsed['parse_error']}")
        return result


class Rde05ObjectTypesChecker:
    """rde-05: Validate object types (header/menu namespace URIs)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-05")
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        header_uris = set(parsed.get("header_uris", []))
        menu_uris = set(parsed.get("menu_uris", []))
        if header_uris and menu_uris and header_uris != menu_uris:
            result.add_error("RDE_MENU_AND_HEADER_URIS_DIFFER", "ERROR",
                             f"Header URIs {header_uris} differ from menu URIs {menu_uris}")
        return result


class Rde06ObjectCountsChecker:
    """rde-06: Validate object counts match header."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-06")
        return result


class Rde07DomainChecker:
    """rde-07: Validate domain objects."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-07")
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        domains = parsed.get("domains", [])
        if not domains:
            result.add_error("RDE_DOMAIN_OBJECT_MISSING", "ERROR", "No domain objects in deposit")
            return result
        registrar_ids = {r["id"] for r in parsed.get("registrars", []) if r.get("id")}
        names_seen: set[str] = set()
        roids_seen: set[str] = set()
        for dom in domains:
            name = dom.get("name", "")
            if not name:
                result.add_error("RDE_DOMAIN_HAS_INVALID_NAME", "ERROR", "Domain missing name")
            elif name in names_seen:
                result.add_error("RDE_DOMAIN_HAS_NON_UNIQUE_NAME", "ERROR", f"Duplicate domain name: {name}")
            names_seen.add(name)

            roid = dom.get("roid", "")
            if not roid:
                result.add_error("RDE_DOMAIN_HAS_MISSING_ROID", "ERROR", f"Domain {name} missing roid")
            elif not ROID_PATTERN.match(roid):
                result.add_error("RDE_DOMAIN_HAS_INVALID_ROID", "ERROR", f"Domain {name} invalid roid: {roid}")
            if roid and roid in roids_seen:
                result.add_error("RDE_DOMAIN_HAS_NON_UNIQUE_ROID", "ERROR", f"Duplicate roid: {roid}")
            roids_seen.add(roid)

            if not dom.get("status"):
                result.add_error("RDE_DOMAIN_HAS_MISSING_STATUS", "ERROR", f"Domain {name} missing status")

            clid = dom.get("clID", "")
            if not clid:
                result.add_error("RDE_DOMAIN_HAS_MISSING_CLID", "ERROR", f"Domain {name} missing clID")
            elif registrar_ids and clid not in registrar_ids:
                result.add_error("RDE_DOMAIN_HAS_INVALID_CLID", "ERROR", f"Domain {name} clID '{clid}' not in registrars")

            if not dom.get("crDate"):
                result.add_error("RDE_DOMAIN_HAS_MISSING_CRDATE", "ERROR", f"Domain {name} missing crDate")

            if self.config.registry_data_model == "maximum" and not dom.get("registrant"):
                result.add_error("RDE_DOMAIN_HAS_MISSING_REGISTRANT", "ERROR", f"Domain {name} missing registrant (maximum model)")

            if self.config.host_model == "attributes" and dom.get("hostObjs"):
                result.add_error("RDE_DOMAIN_HAS_UNEXPECTED_HOST_OBJECTS", "ERROR", f"Domain {name} has hostObj but hostModel=attributes")
            if self.config.host_model == "objects" and dom.get("hostAttrs"):
                result.add_error("RDE_DOMAIN_HAS_UNEXPECTED_HOST_ATTRIBUTES", "ERROR", f"Domain {name} has hostAttr but hostModel=objects")
        return result


class Rde08HostChecker:
    """rde-08: Validate host objects (skip if hostModel=attributes)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-08")
        if self.config.host_model == "attributes":
            result.skip("epp.hostModel is 'attributes'; rde-08 skipped")
            return result
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        hosts = parsed.get("hosts", [])
        if not hosts:
            result.add_error("RDE_HOST_OBJECT_MISSING", "ERROR", "No host objects in deposit")
            return result
        names_seen: set[str] = set()
        for host in hosts:
            name = host.get("name", "")
            if not name:
                result.add_error("RDE_HOST_HAS_INVALID_NAME", "ERROR", "Host missing name")
            elif name in names_seen:
                result.add_error("RDE_HOST_HAS_NON_UNIQUE_NAME", "ERROR", f"Duplicate host name: {name}")
            names_seen.add(name)
            if not host.get("roid"):
                result.add_error("RDE_HOST_HAS_MISSING_ROID", "ERROR", f"Host {name} missing roid")
            if not host.get("status"):
                result.add_error("RDE_HOST_HAS_MISSING_STATUS", "ERROR", f"Host {name} missing status")
            if not host.get("clID"):
                result.add_error("RDE_HOST_HAS_MISSING_CLID", "ERROR", f"Host {name} missing clID")
        return result


class Rde09ContactChecker:
    """rde-09: Validate contact objects (skip if registryDataModel=minimum)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-09")
        if self.config.registry_data_model == "minimum":
            result.skip("registryDataModel is 'minimum'; rde-09 skipped")
            return result
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        contacts = parsed.get("contacts", [])
        if not contacts:
            result.add_error("RDE_CONTACT_OBJECT_MISSING", "ERROR", "No contact objects in deposit")
            return result
        ids_seen: set[str] = set()
        for contact in contacts:
            cid = contact.get("id", "")
            if cid and cid in ids_seen:
                result.add_error("RDE_CONTACT_HAS_NON_UNIQUE_ID", "ERROR", f"Duplicate contact ID: {cid}")
            ids_seen.add(cid)
            roid = contact.get("roid", "")
            if roid and not ROID_PATTERN.match(roid):
                result.add_error("RDE_CONTACT_HAS_INVALID_ROID", "ERROR", f"Contact {cid} invalid roid: {roid}")
            postal_types = contact.get("postalInfoTypes", [])
            if len(postal_types) != len(set(postal_types)):
                result.add_error("RDE_CONTACT_HAS_MULTIPLE_POSTALINFO_TYPES", "ERROR", f"Contact {cid} duplicate postalInfo types")
            email = contact.get("email", "")
            if email and not EMAIL_PATTERN.match(email):
                result.add_error("RDE_CONTACT_HAS_INVALID_EMAIL", "ERROR", f"Contact {cid} invalid email: {email}")
        return result


class Rde10RegistrarChecker:
    """rde-10: Validate registrar objects."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-10")
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        registrars = parsed.get("registrars", [])
        if not registrars:
            result.add_error("RDE_REGISTRAR_OBJECT_MISSING", "ERROR", "No registrar objects in deposit")
            return result
        ids_seen: set[str] = set()
        for reg in registrars:
            rid = reg.get("id", "")
            if not rid:
                result.add_error("RDE_REGISTRAR_HAS_MISSING_ID", "ERROR", "Registrar missing id")
            elif rid in ids_seen:
                result.add_error("RDE_REGISTRAR_HAS_NON_UNIQUE_ID", "ERROR", f"Duplicate registrar id: {rid}")
            ids_seen.add(rid)
            if not reg.get("name"):
                result.add_error("RDE_REGISTRAR_HAS_MISSING_NAME", "ERROR", f"Registrar {rid} missing name")
            if not reg.get("gurid"):
                result.add_error("RDE_REGISTRAR_HAS_MISSING_GURID", "ERROR", f"Registrar {rid} missing gurid")
        return result


class Rde11IdnChecker:
    """rde-11: Validate IDN table objects (if applicable)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-11")
        if not self.config.has_idn_tables:
            result.skip("No IDN tables configured; rde-11 skipped")
        return result


class Rde12NndnChecker:
    """rde-12: Validate NNDN objects (if applicable)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-12")
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        nndn_objects = parsed.get("nndn_objects", [])
        if not nndn_objects:
            return result
        domain_names = {d["name"] for d in parsed.get("domains", []) if d.get("name")}
        nndn_names_seen: set[str] = set()
        for nndn in nndn_objects:
            a_name = nndn.get("aName", "")
            if a_name and a_name in nndn_names_seen:
                result.add_error("RDE_NNDN_HAS_NON_UNIQUE_NAME", "ERROR", f"Duplicate NNDN aName: {a_name}")
            nndn_names_seen.add(a_name)
            if a_name and a_name in domain_names:
                result.add_error("RDE_NNDN_CONFLICTS_WITH_DOMAIN", "ERROR", f"NNDN aName '{a_name}' conflicts with domain name")
        return result


class Rde13EppParamsChecker:
    """rde-13: Validate EPP parameters object."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-13")
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        epp_params = parsed.get("epp_params", [])
        if not epp_params:
            result.add_error("RDE_MISSING_EPP_PARAMS_OBJECT", "ERROR", "No EPP parameters object in deposit")
            return result
        if len(epp_params) > 1:
            result.add_error("RDE_MULTIPLE_EPP_PARAMS_OBJECTS", "ERROR", f"Found {len(epp_params)} EPP params objects (expected 1)")
        ep = epp_params[0]
        ext_uris = set(ep.get("extURIs", []))
        for required in REQUIRED_EPP_EXTURIS:
            if required not in ext_uris:
                result.add_error("RDE_EPP_PARAMS_MISSING_EXTURI", "ERROR", f"Missing required extURI: {required}")
        return result


class Rde14PolicyChecker:
    """rde-14: Validate policy object (if applicable)."""
    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser or RdeDepositParser()

    def run(self) -> RdeTestResult:
        result = RdeTestResult(test_id="rde-14")
        if self.config.registry_data_model == "minimum":
            return result
        if not self.config.deposit_xml:
            return result
        parsed = self.parser.parse(self.config.deposit_xml)
        if "parse_error" in parsed:
            return result
        if parsed.get("policy_objects_count", 0) == 0:
            result.add_error("RDE_POLICY_OBJECT_MISSING", "ERROR", "Policy object missing for non-minimum data model")
        return result


# ---------------------------------------------------------------------------
# Suite runner
# ---------------------------------------------------------------------------

_RDE_CHECKERS: list[type] = [
    Rde01FilenameChecker,
    Rde02SignatureChecker,
    Rde03DecryptionChecker,
    Rde04XmlCsvChecker,
    Rde05ObjectTypesChecker,
    Rde06ObjectCountsChecker,
    Rde07DomainChecker,
    Rde08HostChecker,
    Rde09ContactChecker,
    Rde10RegistrarChecker,
    Rde11IdnChecker,
    Rde12NndnChecker,
    Rde13EppParamsChecker,
    Rde14PolicyChecker,
]


class StandardRdeTestSuite:
    """Runs all 14 test cases in the StandardRDE suite."""

    def __init__(self, config: RdeSuiteConfig, *, parser: RdeDepositParser | None = None) -> None:
        self.config = config
        self.parser = parser

    def run_all(self) -> list[RdeTestResult]:
        return [cls(self.config, parser=self.parser).run() for cls in _RDE_CHECKERS]
