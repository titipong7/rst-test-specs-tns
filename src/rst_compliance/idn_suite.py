"""StandardIDN test suite checkers for RST v2026.04.

Implements both IDN test cases from the RST specification:
  - idn-01: IDN label validation and variant policy checks
  - idn-02: ASCII domains in IDN-only TLD rejection

All checkers follow the same dependency-injection pattern as RDAP/DNS/RDE suites.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from rst_compliance.epp_client import EppClient


@dataclass(frozen=True)
class IdnTestError:
    """Structured error produced by any IDN test case."""
    code: str
    severity: str
    detail: str


@dataclass
class IdnTestResult:
    """Aggregated result of a single IDN test case run."""
    test_id: str
    passed: bool = True
    skipped: bool = False
    errors: list[IdnTestError] = field(default_factory=list)

    def add_error(self, code: str, severity: str, detail: str) -> None:
        self.errors.append(IdnTestError(code=code, severity=severity, detail=detail))
        if severity in ("ERROR", "CRITICAL"):
            self.passed = False

    def skip(self, reason: str) -> None:
        self.skipped = True
        self.errors.append(IdnTestError(code="SKIPPED", severity="INFO", detail=reason))


@dataclass(frozen=True)
class IdnDomainCreateObservation:
    """Observed EPP create behavior for one generated IDN label."""
    domain: str
    expected_valid: bool
    accepted: bool
    detail: str = ""


@dataclass(frozen=True)
class IdnVariantObservation:
    """Observed EPP create behavior for one generated variant label."""
    domain: str
    policy: str
    same_registrar: bool
    same_registrant: bool
    accepted: bool


@dataclass(frozen=True)
class IdnAsciiCreateObservation:
    """Observed EPP create behavior for an ASCII label under a TLD."""
    domain: str
    tld: str
    idn_only: bool
    accepted: bool


@dataclass(frozen=True)
class IdnSuiteConfig:
    """Unified configuration for the StandardIDN test suite."""
    domain_create_extension_xml: str | None = None
    domain_create_observations: list[IdnDomainCreateObservation] = field(default_factory=list)
    variant_observations: list[IdnVariantObservation] = field(default_factory=list)
    ascii_create_observations: list[IdnAsciiCreateObservation] = field(default_factory=list)


def _validate_extension(result: IdnTestResult, extension_xml: str | None) -> None:
    if not extension_xml:
        return
    try:
        EppClient.validate_extension_xml(extension_xml)
    except ValueError as exc:
        result.add_error("EPP_INVALID_IDN_EXTENSION", "ERROR", str(exc))


class Idn01LabelValidationChecker:
    """idn-01: IDN label validation and variant policy checks."""
    def __init__(self, config: IdnSuiteConfig) -> None:
        self.config = config

    def run(self) -> IdnTestResult:
        result = IdnTestResult(test_id="idn-01")
        _validate_extension(result, self.config.domain_create_extension_xml)

        if not self.config.domain_create_observations and not self.config.variant_observations:
            result.add_error("IDN_NO_LABEL_OBSERVATIONS", "ERROR", "No generated IDN label observations were provided.")
            return result

        for observation in self.config.domain_create_observations:
            if observation.expected_valid and not observation.accepted:
                result.add_error(
                    "IDN_SERVER_REJECTS_VALID_LABEL",
                    "ERROR",
                    f"Server rejected valid IDN label {observation.domain}. {observation.detail}".strip(),
                )
            if not observation.expected_valid and observation.accepted:
                result.add_error(
                    "IDN_SERVER_ACCEPTS_INVALID_LABEL",
                    "ERROR",
                    f"Server accepted invalid IDN label {observation.domain}. {observation.detail}".strip(),
                )

        for observation in self.config.variant_observations:
            policy = observation.policy.lower()
            if policy == "blocked":
                if observation.accepted:
                    result.add_error(
                        "IDN_VARIANT_LABEL_NOT_BLOCKED",
                        "ERROR",
                        f"Variant label {observation.domain} was accepted but policy requires blocking.",
                    )
            elif policy == "same-registrant":
                if observation.same_registrant and not observation.accepted:
                    result.add_error(
                        "IDN_VARIANT_SERVER_REJECTS_VARIANT_CREATE_WITH_SAME_REGISTRANT",
                        "ERROR",
                        f"Variant label {observation.domain} was rejected for the same registrant.",
                    )
                if not observation.same_registrant and observation.accepted:
                    result.add_error(
                        "IDN_VARIANT_SERVER_ACCEPTS_VARIANT_CREATE_WITH_INCORRECT_REGISTRANT",
                        "ERROR",
                        f"Variant label {observation.domain} was accepted for a different registrant.",
                    )
            elif policy == "same-registrar":
                if observation.same_registrar and not observation.accepted:
                    result.add_error(
                        "IDN_VARIANT_SERVER_REJECTS_VARIANT_CREATE_FROM_SAME_REGISTRAR",
                        "ERROR",
                        f"Variant label {observation.domain} was rejected for the same registrar.",
                    )
                if not observation.same_registrar and observation.accepted:
                    result.add_error(
                        "IDN_VARIANT_SERVER_ACCEPTS_VARIANT_CREATE_FROM_INCORRECT_REGISTRAR",
                        "ERROR",
                        f"Variant label {observation.domain} was accepted for a different registrar.",
                    )
            else:
                result.add_error("IDN_UNKNOWN_VARIANT_POLICY", "ERROR", f"Unknown variant policy: {observation.policy}")
        return result


class Idn02AsciiIdnOnlyChecker:
    """idn-02: ASCII domains in IDN-only TLD rejection."""
    def __init__(self, config: IdnSuiteConfig) -> None:
        self.config = config

    def run(self) -> IdnTestResult:
        result = IdnTestResult(test_id="idn-02")
        applicable = [item for item in self.config.ascii_create_observations if item.idn_only]
        if not applicable:
            result.skip("No TLDs with idnOnly=true were provided; idn-02 skipped.")
            return result

        for observation in applicable:
            if observation.accepted:
                result.add_error(
                    "IDN_IDNONLY_TLD_ACCEPTS_ASCII_DOMAIN",
                    "ERROR",
                    f"IDN-only TLD {observation.tld} accepted ASCII domain {observation.domain}.",
                )
        return result


_IDN_CHECKERS = [
    Idn01LabelValidationChecker,
    Idn02AsciiIdnOnlyChecker,
]


class StandardIdnTestSuite:
    """Runs all test cases in the StandardIDN suite."""
    def __init__(self, config: IdnSuiteConfig) -> None:
        self.config = config

    def run_all(self) -> list[IdnTestResult]:
        return [checker_cls(self.config).run() for checker_cls in _IDN_CHECKERS]
