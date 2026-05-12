"""StandardIntegrationTest suite checkers for RST v2026.04.

Implements all five integration test cases from the RST specification:
  - integration-01: EPP to RDAP propagation
  - integration-02: EPP to DNS propagation
  - integration-03: EPP to RDE propagation
  - integration-04: Narrow glue policy for host objects
  - integration-05: Narrow glue policy for host attributes

All checkers follow the same dependency-injection pattern as RDAP/DNS/RDE suites.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class IntegrationTestError:
    """Structured error produced by any integration test case."""
    code: str
    severity: str
    detail: str


@dataclass
class IntegrationTestResult:
    """Aggregated result of a single integration test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[IntegrationTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(IntegrationTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(IntegrationTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class RdapPropagationObservation:
    object_name: str
    object_type: str
    http_status: int
    present: bool
    within_sla: bool = True


@dataclass(frozen=True)
class DnsPropagationObservation:
    domain: str
    server: str
    response_present: bool
    query_succeeded: bool = True
    within_sla: bool = True


@dataclass(frozen=True)
class RdePropagationObservation:
    object_name: str
    present_in_deposit: bool
    sftp_reachable: bool = True
    authenticated: bool = True
    within_sla: bool = True


@dataclass(frozen=True)
class GluePolicyObservation:
    host_name: str
    should_be_published: bool
    observed_in_dns: bool


@dataclass(frozen=True)
class IntegrationSuiteConfig:
    """Unified configuration for the StandardIntegrationTest suite."""
    glue_policy: str = "narrow"
    host_model: str = "objects"
    rdap_observations: list[RdapPropagationObservation] = field(default_factory=list)
    dns_observations: list[DnsPropagationObservation] = field(default_factory=list)
    rde_observations: list[RdePropagationObservation] = field(default_factory=list)
    host_object_glue_observations: list[GluePolicyObservation] = field(default_factory=list)
    host_attribute_glue_observations: list[GluePolicyObservation] = field(default_factory=list)


class Integration01RdapPropagationChecker:
    """integration-01: EPP-created objects are present in RDAP within SLA."""
    def __init__(self, config: IntegrationSuiteConfig) -> None:
        self.config = config

    def run(self) -> IntegrationTestResult:
        result = IntegrationTestResult(test_id="integration-01")
        if not self.config.rdap_observations:
            result.add_error("INTEGRATION_NO_RDAP_OBSERVATIONS", "ERROR", "No RDAP propagation observations were provided.")
            return result
        for observation in self.config.rdap_observations:
            if observation.http_status != 200:
                result.add_error("INTEGRATION_RDAP_REQUEST_FAILED", "ERROR", f"RDAP query for {observation.object_name} returned {observation.http_status}.")
            if not observation.present:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDAP", "ERROR", f"{observation.object_type} {observation.object_name} was not present in RDAP.")
            if not observation.within_sla:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDAP", "ERROR", f"{observation.object_name} was not present in RDAP within SLA.")
        return result


class Integration02DnsPropagationChecker:
    """integration-02: EPP-created domains are present in DNS within SLA."""
    def __init__(self, config: IntegrationSuiteConfig) -> None:
        self.config = config

    def run(self) -> IntegrationTestResult:
        result = IntegrationTestResult(test_id="integration-02")
        if not self.config.dns_observations:
            result.add_error("INTEGRATION_NO_DNS_OBSERVATIONS", "ERROR", "No DNS propagation observations were provided.")
            return result
        for observation in self.config.dns_observations:
            if not observation.query_succeeded:
                result.add_error("INTEGRATION_DNS_QUERY_FAILED", "ERROR", f"DNS query for {observation.domain} at {observation.server} failed.")
            if not observation.response_present:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_DNS", "ERROR", f"{observation.domain} was not present at {observation.server}.")
            if not observation.within_sla:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_DNS", "ERROR", f"{observation.domain} was not present in DNS within SLA.")
        return result


class Integration03RdePropagationChecker:
    """integration-03: EPP-created objects are present in RDE within SLA."""
    def __init__(self, config: IntegrationSuiteConfig) -> None:
        self.config = config

    def run(self) -> IntegrationTestResult:
        result = IntegrationTestResult(test_id="integration-03")
        if not self.config.rde_observations:
            result.add_error("INTEGRATION_NO_RDE_OBSERVATIONS", "ERROR", "No RDE propagation observations were provided.")
            return result
        for observation in self.config.rde_observations:
            if not observation.sftp_reachable:
                result.add_error("INTEGRATION_RDE_SFTP_SERVER_UNREACHABLE", "ERROR", "RDE SFTP server was unreachable.")
            if not observation.authenticated:
                result.add_error("INTEGRATION_RDE_SFTP_SERVER_AUTHENTICATION_ERROR", "ERROR", "RDE SFTP authentication failed.")
            if not observation.present_in_deposit:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDE", "ERROR", f"{observation.object_name} was not present in RDE deposit.")
            if not observation.within_sla:
                result.add_error("INTEGRATION_DOMAIN_NOT_PRESENT_IN_RDE", "ERROR", f"{observation.object_name} was not present in RDE within SLA.")
        return result


class _GluePolicyChecker:
    test_id = ""
    expected_host_model = ""
    expected_error_code = ""
    unexpected_error_code = ""

    def __init__(self, config: IntegrationSuiteConfig) -> None:
        self.config = config

    def _observations(self) -> list[GluePolicyObservation]:
        raise NotImplementedError

    def run(self) -> IntegrationTestResult:
        result = IntegrationTestResult(test_id=self.test_id)
        if self.config.glue_policy != "narrow" or self.config.host_model != self.expected_host_model:
            result.skip(f"dns.gluePolicy={self.config.glue_policy!r} and epp.hostModel={self.config.host_model!r}; {self.test_id} not applicable.")
            return result
        observations = self._observations()
        if not observations:
            result.add_error("INTEGRATION_NO_GLUE_OBSERVATIONS", "ERROR", f"No glue policy observations were provided for {self.test_id}.")
            return result
        for observation in observations:
            if observation.should_be_published and not observation.observed_in_dns:
                result.add_error(self.expected_error_code, "ERROR", f"Expected glue {observation.host_name} was not observed in DNS.")
            if not observation.should_be_published and observation.observed_in_dns:
                result.add_error(self.unexpected_error_code, "ERROR", f"Unexpected glue {observation.host_name} was observed in DNS.")
        return result


class Integration04HostObjectGlueChecker(_GluePolicyChecker):
    """integration-04: Narrow glue policy for host objects."""
    test_id = "integration-04"
    expected_host_model = "objects"
    expected_error_code = "INTEGRATION_LINKED_HOST_OBJECTS_NOT_OBSERVED"
    unexpected_error_code = "INTEGRATION_UNLINKED_HOST_OBJECTS_OBSERVED"

    def _observations(self) -> list[GluePolicyObservation]:
        return self.config.host_object_glue_observations


class Integration05HostAttributeGlueChecker(_GluePolicyChecker):
    """integration-05: Narrow glue policy for host attributes."""
    test_id = "integration-05"
    expected_host_model = "attributes"
    expected_error_code = "INTEGRATION_EXPECTED_GLUE_NOT_OBSERVED"
    unexpected_error_code = "INTEGRATION_UNEXPECTED_GLUE_OBSERVED"

    def _observations(self) -> list[GluePolicyObservation]:
        return self.config.host_attribute_glue_observations


_INTEGRATION_CHECKERS = [
    Integration01RdapPropagationChecker,
    Integration02DnsPropagationChecker,
    Integration03RdePropagationChecker,
    Integration04HostObjectGlueChecker,
    Integration05HostAttributeGlueChecker,
]


class StandardIntegrationTestSuite:
    """Runs all test cases in the StandardIntegrationTest suite."""
    def __init__(self, config: IntegrationSuiteConfig) -> None:
        self.config = config

    def run_all(self) -> list[IntegrationTestResult]:
        return [checker_cls(self.config).run() for checker_cls in _INTEGRATION_CHECKERS]
