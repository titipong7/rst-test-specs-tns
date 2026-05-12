"""StandardSRSGateway test suite checkers for RST v2026.04.

Implements the 14 SRS Gateway cases from the RST specification:
  - srsgw-01: IPv4 and IPv6 connectivity
  - srsgw-02..06, 08..12: EPP object synchronization
  - srsgw-13..15: RDAP synchronization

All checkers follow the same dependency-injection pattern as RDAP/DNS/RDE suites.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SrsgwTestError:
    """Structured error produced by any SRS Gateway test case."""
    code: str
    severity: str
    detail: str


@dataclass
class SrsgwTestResult:
    """Aggregated result of a single SRS Gateway test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[SrsgwTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(SrsgwTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(SrsgwTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class SrsgwConnectivityObservation:
    ip_version: str
    reachable: bool
    tls_ok: bool = True
    login_ok: bool = True


@dataclass(frozen=True)
class SrsgwSyncObservation:
    case_id: str
    object_name: str
    gateway_command_code: int
    primary_info_code: int = 1000
    found_within_deadline: bool = True
    properties_match: bool = True
    applicable: bool = True


@dataclass(frozen=True)
class SrsgwRdapObservation:
    case_id: str
    object_name: str
    http_status: int
    present: bool
    properties_match: bool = True
    applicable: bool = True


@dataclass(frozen=True)
class SrsgwSuiteConfig:
    """Unified configuration for the StandardSRSGateway test suite."""
    host_model: str = "objects"
    registry_data_model: str = "maximum"
    connectivity_observations: list[SrsgwConnectivityObservation] = field(default_factory=list)
    sync_observations: list[SrsgwSyncObservation] = field(default_factory=list)
    rdap_observations: list[SrsgwRdapObservation] = field(default_factory=list)


def _success_code(code: int) -> bool:
    return 1000 <= code < 2000


class Srsgw01ConnectivityChecker:
    """srsgw-01: IPv4 and IPv6 connectivity."""
    def __init__(self, config: SrsgwSuiteConfig) -> None:
        self.config = config

    def run(self) -> SrsgwTestResult:
        result = SrsgwTestResult(test_id="srsgw-01")
        by_version = {item.ip_version.lower(): item for item in self.config.connectivity_observations}
        for ip_version in ("ipv4", "ipv6"):
            observation = by_version.get(ip_version)
            if observation is None:
                result.add_error("EPP_NO_SERVICE_PORTS_REACHABLE", "ERROR", f"No {ip_version} SRS Gateway connectivity observation was provided.")
                continue
            if not observation.reachable:
                result.add_error("EPP_SERVICE_PORT_UNREACHABLE", "ERROR", f"SRS Gateway {ip_version} service port was unreachable.")
            if not observation.tls_ok:
                result.add_error("EPP_TLS_CONNECTION_ERROR", "ERROR", f"SRS Gateway {ip_version} TLS handshake failed.")
            if not observation.login_ok:
                result.add_error("EPP_LOGIN_ERROR", "ERROR", f"SRS Gateway {ip_version} login failed.")
        return result


class _SrsgwSyncChecker:
    test_id = ""
    failure_code = ""
    missing_code = ""
    invalid_properties_code = ""

    def __init__(self, config: SrsgwSuiteConfig) -> None:
        self.config = config

    def _applicable(self) -> tuple[bool, str]:
        return True, ""

    def run(self) -> SrsgwTestResult:
        result = SrsgwTestResult(test_id=self.test_id)
        applicable, reason = self._applicable()
        if not applicable:
            result.skip(reason)
            return result
        observations = [item for item in self.config.sync_observations if item.case_id == self.test_id]
        if not observations:
            result.add_error("SRSGW_NO_SYNC_OBSERVATIONS", "ERROR", f"No synchronization observations were provided for {self.test_id}.")
            return result
        for observation in observations:
            if not observation.applicable:
                result.skip(f"{self.test_id} observation for {observation.object_name} is not applicable.")
                continue
            if not _success_code(observation.gateway_command_code):
                result.add_error(self.failure_code, "ERROR", f"Gateway command for {observation.object_name} returned {observation.gateway_command_code}.")
            if observation.primary_info_code != 1000 or not observation.found_within_deadline:
                result.add_error(self.missing_code, "ERROR", f"Primary registry did not return {observation.object_name} within deadline.")
            if not observation.properties_match:
                result.add_error(self.invalid_properties_code, "ERROR", f"Gateway and primary properties differ for {observation.object_name}.")
        return result


class _HostObjectSyncChecker(_SrsgwSyncChecker):
    def _applicable(self) -> tuple[bool, str]:
        if self.config.host_model == "attributes":
            return False, "epp.hostModel is 'attributes'; host object synchronization not applicable."
        return True, ""


class _ContactSyncChecker(_SrsgwSyncChecker):
    def _applicable(self) -> tuple[bool, str]:
        if self.config.registry_data_model == "minimum":
            return False, "srsgw.registryDataModel is 'minimum'; contact synchronization not applicable."
        return True, ""


class Srsgw02HostCreateChecker(_HostObjectSyncChecker):
    """srsgw-02: Host create synchronization."""
    test_id = "srsgw-02"
    failure_code = "SRSGW_HOST_CREATE_FAILED"
    missing_code = "SRSGW_HOST_CREATE_OBJECT_NOT_FOUND_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_HOST_CREATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw03ContactCreateChecker(_ContactSyncChecker):
    """srsgw-03: Contact create synchronization."""
    test_id = "srsgw-03"
    failure_code = "SRSGW_CONTACT_CREATE_FAILED"
    missing_code = "SRSGW_CONTACT_CREATE_OBJECT_NOT_FOUND_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_CONTACT_CREATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw04DomainCreateChecker(_SrsgwSyncChecker):
    """srsgw-04: Domain create synchronization."""
    test_id = "srsgw-04"
    failure_code = "SRSGW_DOMAIN_CREATE_FAILED"
    missing_code = "SRSGW_DOMAIN_CREATE_OBJECT_NOT_FOUND_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_DOMAIN_CREATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw05DomainRenewChecker(_SrsgwSyncChecker):
    """srsgw-05: Domain renew synchronization."""
    test_id = "srsgw-05"
    failure_code = "SRSGW_DOMAIN_RENEW_FAILED"
    missing_code = "SRSGW_DOMAIN_RENEW_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_DOMAIN_RENEW_INCORRECT_EXPIRY_DATE"


class Srsgw06DomainTransferChecker(_SrsgwSyncChecker):
    """srsgw-06: Domain transfer synchronization."""
    test_id = "srsgw-06"
    failure_code = "SRSGW_DOMAIN_TRANSFER_FAILED"
    missing_code = "SRSGW_DOMAIN_TRANSFER_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_DOMAIN_TRANSFER_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw08DomainDeleteChecker(_SrsgwSyncChecker):
    """srsgw-08: Domain delete synchronization."""
    test_id = "srsgw-08"
    failure_code = "SRSGW_DOMAIN_DELETE_FAILED"
    missing_code = "SRSGW_DOMAIN_DELETE_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_DOMAIN_DELETE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw09HostUpdateChecker(_HostObjectSyncChecker):
    """srsgw-09: Host update synchronization."""
    test_id = "srsgw-09"
    failure_code = "SRSGW_HOST_UPDATE_FAILED"
    missing_code = "SRSGW_HOST_UPDATE_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_HOST_UPDATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw10HostDeleteChecker(_HostObjectSyncChecker):
    """srsgw-10: Host delete synchronization."""
    test_id = "srsgw-10"
    failure_code = "SRSGW_HOST_DELETE_FAILED"
    missing_code = "SRSGW_HOST_DELETE_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_HOST_DELETE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw11ContactUpdateChecker(_ContactSyncChecker):
    """srsgw-11: Contact update synchronization."""
    test_id = "srsgw-11"
    failure_code = "SRSGW_CONTACT_UPDATE_FAILED"
    missing_code = "SRSGW_CONTACT_UPDATE_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_CONTACT_UPDATE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw12ContactDeleteChecker(_ContactSyncChecker):
    """srsgw-12: Contact delete synchronization."""
    test_id = "srsgw-12"
    failure_code = "SRSGW_CONTACT_DELETE_FAILED"
    missing_code = "SRSGW_CONTACT_DELETE_OBJECT_NOT_UPDATED_WITHIN_DEADLINE"
    invalid_properties_code = "SRSGW_CONTACT_DELETE_OBJECT_HAS_MISSING_OR_INVALID_PROPERTIES"


class _SrsgwRdapChecker:
    test_id = ""
    request_failed_code = "SRSGW_RDAP_REQUEST_FAILED"
    missing_code = ""
    invalid_properties_code = ""

    def __init__(self, config: SrsgwSuiteConfig) -> None:
        self.config = config

    def run(self) -> SrsgwTestResult:
        result = SrsgwTestResult(test_id=self.test_id)
        observations = [item for item in self.config.rdap_observations if item.case_id == self.test_id]
        if not observations:
            result.add_error("SRSGW_NO_RDAP_OBSERVATIONS", "ERROR", f"No RDAP observations were provided for {self.test_id}.")
            return result
        for observation in observations:
            if not observation.applicable:
                result.skip(f"{self.test_id} observation for {observation.object_name} is not applicable.")
                continue
            if observation.http_status != 200:
                result.add_error(self.request_failed_code, "ERROR", f"RDAP query for {observation.object_name} returned {observation.http_status}.")
            if not observation.present:
                result.add_error(self.missing_code, "ERROR", f"{observation.object_name} was not present in RDAP.")
            if not observation.properties_match:
                result.add_error(self.invalid_properties_code, "ERROR", f"RDAP properties differ for {observation.object_name}.")
        return result


class Srsgw13DomainRdapChecker(_SrsgwRdapChecker):
    """srsgw-13: Domain RDAP synchronization."""
    test_id = "srsgw-13"
    missing_code = "SRSGW_DOMAIN_NOT_PRESENT_IN_RDAP"
    invalid_properties_code = "SRSGW_DOMAIN_RDAP_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw14NameserverRdapChecker(_SrsgwRdapChecker):
    """srsgw-14: Nameserver RDAP synchronization."""
    test_id = "srsgw-14"
    missing_code = "SRSGW_NAMESERVER_NOT_PRESENT_IN_RDAP"
    invalid_properties_code = "SRSGW_NAMESERVER_RDAP_HAS_MISSING_OR_INVALID_PROPERTIES"


class Srsgw15RegistrarRdapChecker(_SrsgwRdapChecker):
    """srsgw-15: Registrar RDAP synchronization."""
    test_id = "srsgw-15"
    missing_code = "SRSGW_REGISTRAR_NOT_PRESENT_IN_RDAP"
    invalid_properties_code = "SRSGW_REGISTRAR_RDAP_HAS_MISSING_OR_INVALID_PROPERTIES"


_SRSGW_CHECKERS = [
    Srsgw01ConnectivityChecker,
    Srsgw02HostCreateChecker,
    Srsgw03ContactCreateChecker,
    Srsgw04DomainCreateChecker,
    Srsgw05DomainRenewChecker,
    Srsgw06DomainTransferChecker,
    Srsgw08DomainDeleteChecker,
    Srsgw09HostUpdateChecker,
    Srsgw10HostDeleteChecker,
    Srsgw11ContactUpdateChecker,
    Srsgw12ContactDeleteChecker,
    Srsgw13DomainRdapChecker,
    Srsgw14NameserverRdapChecker,
    Srsgw15RegistrarRdapChecker,
]


class StandardSrsgwTestSuite:
    """Runs all test cases in the StandardSRSGateway suite."""
    def __init__(self, config: SrsgwSuiteConfig) -> None:
        self.config = config

    def run_all(self) -> list[SrsgwTestResult]:
        return [checker_cls(self.config).run() for checker_cls in _SRSGW_CHECKERS]
