from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
import socket
import ssl
import xml.etree.ElementTree as ET
import re


REQUIRED_KEY_ALGORITHM = "RSA"
REQUIRED_KEY_SIZE_BITS = 4096
RECV_BUFFER_SIZE = 4096
DOMAIN_OBJ_URI = "urn:ietf:params:xml:ns:domain-1.0"
REQUIRED_EXT_URIS = (
    "urn:ietf:params:xml:ns:secDNS-1.1",
    "urn:ietf:params:xml:ns:rgp-1.0",
)
RECOMMENDED_EXT_URIS = (
    "urn:ietf:params:xml:ns:epp:secure-authinfo-transfer-1.0",
    "urn:ietf:params:xml:ns:epp:unhandled-namespaces-1.0",
    "urn:ietf:params:xml:ns:epp:loginSec-1.0",
    "urn:ietf:params:xml:ns:changePoll-1.0",
)
LANG_CODE_RE = re.compile(r"^[A-Za-z]{2}(?:-[A-Za-z]{2})?$")
EPP02_ERROR_SEVERITY = {
    "EPP_NO_GREETING_RECEIVED": "ERROR",
    "EPP_XML_PARSE_ERROR": "ERROR",
    "EPP_GREETING_SVID_INVALID": "ERROR",
    "EPP_GREETING_SVDATE_INVALID": "ERROR",
    "EPP_GREETING_VERSION_INVALID": "ERROR",
    "EPP_GREETING_INVALID_LANG": "ERROR",
    "EPP_GREETING_MISSING_EN_LANG": "ERROR",
    "EPP_GREETING_MISSING_OBJURI": "ERROR",
    "EPP_GREETING_UNEXPECTED_OBJURI": "ERROR",
    "EPP_GREETING_MISSING_EXTURI": "ERROR",
    "EPP_GREETING_UNEXPECTED_EXTURI": "ERROR",
    "EPP_GREETING_RECOMMENDED_EXTENSION_MISSING": "WARNING",
}
EPP03_ERROR_SEVERITY = {
    "EPP_LOGIN_UNEXPECTEDLY_FAILED": "ERROR",
    "EPP_LOGIN_UNEXPECTEDLY_SUCCEEDED": "ERROR",
}
EPP04_ERROR_SEVERITY = {
    "EPP_XML_PARSE_ERROR": "ERROR",
    "EPP_DOMAIN_CHECK_INVALID_DOMAIN_INCORRECT_AVAIL": "ERROR",
    "EPP_DOMAIN_CHECK_REGISTERED_DOMAIN_INCORRECT_AVAIL": "ERROR",
    "EPP_DOMAIN_CHECK_VALID_DOMAIN_INCORRECT_AVAIL": "ERROR",
    "EPP_UNEXPECTED_COMMAND_FAILURE": "ERROR",
}
EPP_GENERIC_ERROR_SEVERITY = {
    "EPP_UNEXPECTED_COMMAND_FAILURE": "ERROR",
    "EPP_UNEXPECTED_COMMAND_SUCCESS": "ERROR",
    "EPP_XML_PARSE_ERROR": "ERROR",
}


@dataclass(frozen=True)
class EppMtlsConfig:
    host: str
    client_cert_file: Path
    client_key_file: Path
    ca_cert_file: Path | None = None
    port: int = 700
    timeout_seconds: int = 30
    key_algorithm: str = REQUIRED_KEY_ALGORITHM
    key_size_bits: int = REQUIRED_KEY_SIZE_BITS

    def __post_init__(self) -> None:
        if self.key_algorithm.upper() != REQUIRED_KEY_ALGORITHM:
            raise ValueError(
                f"ICANN 2026 EPP mTLS profile requires RSA client keys, got: {self.key_algorithm}"
            )
        if self.key_size_bits != REQUIRED_KEY_SIZE_BITS:
            raise ValueError(
                f"ICANN 2026 EPP mTLS profile requires 4096-bit client keys, got: {self.key_size_bits} bits"
            )


class EppTransport(Protocol):
    def send(
        self,
        *,
        xml_command: str,
        ssl_context: ssl.SSLContext,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> str: ...


class SocketEppTransport:
    def send(
        self,
        *,
        xml_command: str,
        ssl_context: ssl.SSLContext,
        host: str,
        port: int,
        timeout_seconds: int,
    ) -> str:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(xml_command.encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    chunk = tls_sock.recv(RECV_BUFFER_SIZE)
                    if not chunk:
                        break
                    chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")


class EppClient:
    def __init__(
        self,
        config: EppMtlsConfig,
        transport: EppTransport | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or SocketEppTransport()
        self.ssl_context = ssl_context or self._build_ssl_context()

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=str(self.config.ca_cert_file) if self.config.ca_cert_file else None,
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(
            certfile=str(self.config.client_cert_file),
            keyfile=str(self.config.client_key_file),
        )
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def send_command(self, xml_command: str) -> str:
        return self.transport.send(
            xml_command=xml_command,
            ssl_context=self.ssl_context,
            host=self.config.host,
            port=self.config.port,
            timeout_seconds=self.config.timeout_seconds,
        )

    @staticmethod
    def result_code(response_xml: str) -> int:
        root = ET.fromstring(response_xml)
        result = root.find(".//{*}result")
        if result is None:
            result = root.find(".//result")
        if result is None or "code" not in result.attrib:
            raise ValueError("EPP response missing result code")
        return int(result.attrib["code"])

    @classmethod
    def is_success(cls, response_xml: str) -> bool:
        return 1000 <= cls.result_code(response_xml) < 2000

    def run_login_and_check(self, *, login_xml: str, check_xml: str) -> list["EppCommandCheckResult"]:
        login_response = self.send_command(login_xml)
        check_response = self.send_command(check_xml)
        return [
            assess_epp_command(command_name="login", response_xml=login_response),
            assess_epp_command(command_name="check", response_xml=check_response),
        ]

    @staticmethod
    def validate_extension_xml(extension_xml: str) -> None:
        """Validate basic RST expectations for EPP extension input.

        The input must be a single <extension> element containing one or more
        child extension elements.
        """
        try:
            root = ET.fromstring(extension_xml)
        except ET.ParseError as exc:
            raise ValueError("invalid XML in EPP extension input") from exc

        local_name = root.tag.rsplit("}", 1)[-1]
        if local_name != "extension":
            raise ValueError("EPP extension input must use <extension> as the root element")
        if len(list(root)) == 0:
            raise ValueError("EPP extension input must include at least one child extension element")


@dataclass(frozen=True)
class EppCommandCheckResult:
    command_name: str
    response_code: int
    status: str
    reason: str


@dataclass(frozen=True)
class EppRuleFinding:
    code: str
    severity: str
    message: str


@dataclass(frozen=True)
class EppLoginAttempt:
    scenario: str
    expected_success: bool
    response_xml: str


def assess_epp_command(*, command_name: str, response_xml: str) -> EppCommandCheckResult:
    code = EppClient.result_code(response_xml)
    if 1000 <= code < 2000:
        return EppCommandCheckResult(
            command_name=command_name,
            response_code=code,
            status="pass",
            reason=f"{command_name} command accepted",
        )
    if code == 2306:
        return EppCommandCheckResult(
            command_name=command_name,
            response_code=code,
            status="fail",
            reason=f"{command_name} command rejected by Narrow Glue Policy",
        )
    return EppCommandCheckResult(
        command_name=command_name,
        response_code=code,
        status="fail",
        reason=f"{command_name} command failed with EPP result code {code}",
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child_by_local_name(parent: ET.Element, local_name: str) -> ET.Element | None:
    for child in parent:
        if _local_name(child.tag) == local_name:
            return child
    return None


def _collect_by_local_name(parent: ET.Element, local_name: str) -> list[ET.Element]:
    return [child for child in parent if _local_name(child.tag) == local_name]


def _parse_svdate(raw: str) -> datetime | None:
    try:
        normalized = raw.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        return None


def assess_epp02_greeting(
    greeting_xml: str,
    *,
    expected_server_id: str,
    now_utc: datetime | None = None,
    required_obj_uris: tuple[str, ...] = (DOMAIN_OBJ_URI,),
    required_ext_uris: tuple[str, ...] = REQUIRED_EXT_URIS,
    recommended_ext_uris: tuple[str, ...] = RECOMMENDED_EXT_URIS,
    allow_launch_extension: bool = True,
    extension_registry_uris: set[str] | None = None,
) -> list[EppRuleFinding]:
    findings: list[EppRuleFinding] = []
    if not greeting_xml.strip():
        return [EppRuleFinding("EPP_NO_GREETING_RECEIVED", EPP02_ERROR_SEVERITY["EPP_NO_GREETING_RECEIVED"], "No EPP greeting frame received.")]

    try:
        root = ET.fromstring(greeting_xml)
    except ET.ParseError as exc:
        return [EppRuleFinding("EPP_XML_PARSE_ERROR", EPP02_ERROR_SEVERITY["EPP_XML_PARSE_ERROR"], f"Greeting XML parse failed: {exc}")]

    greeting = root if _local_name(root.tag) == "greeting" else root.find(".//{*}greeting")
    if greeting is None:
        return [EppRuleFinding("EPP_NO_GREETING_RECEIVED", EPP02_ERROR_SEVERITY["EPP_NO_GREETING_RECEIVED"], "Greeting element is missing from EPP frame.")]

    svid = _find_child_by_local_name(greeting, "svID")
    if svid is None or (svid.text or "").strip() != expected_server_id:
        findings.append(EppRuleFinding("EPP_GREETING_SVID_INVALID", EPP02_ERROR_SEVERITY["EPP_GREETING_SVID_INVALID"], "Greeting svID does not match expected server identifier."))

    svdate = _find_child_by_local_name(greeting, "svDate")
    parsed_svdate = _parse_svdate((svdate.text or "").strip()) if svdate is not None else None
    effective_now = now_utc or datetime.now(timezone.utc)
    if parsed_svdate is None or abs((parsed_svdate - effective_now).total_seconds()) > 30:
        findings.append(EppRuleFinding("EPP_GREETING_SVDATE_INVALID", EPP02_ERROR_SEVERITY["EPP_GREETING_SVDATE_INVALID"], "Greeting svDate is missing, invalid, or outside the 30 second tolerance window."))

    svc_menu = _find_child_by_local_name(greeting, "svcMenu")
    if svc_menu is None:
        findings.append(EppRuleFinding("EPP_GREETING_VERSION_INVALID", EPP02_ERROR_SEVERITY["EPP_GREETING_VERSION_INVALID"], "Greeting svcMenu is missing."))
        return findings

    versions = [((item.text or "").strip()) for item in _collect_by_local_name(svc_menu, "version")]
    if len(versions) != 1 or versions[0] != "1.0":
        findings.append(EppRuleFinding("EPP_GREETING_VERSION_INVALID", EPP02_ERROR_SEVERITY["EPP_GREETING_VERSION_INVALID"], "Greeting must include exactly one <version> element set to 1.0."))

    langs = [((item.text or "").strip()) for item in _collect_by_local_name(svc_menu, "lang")]
    if not langs or any(not LANG_CODE_RE.match(lang) for lang in langs):
        findings.append(EppRuleFinding("EPP_GREETING_INVALID_LANG", EPP02_ERROR_SEVERITY["EPP_GREETING_INVALID_LANG"], "Greeting contains missing or invalid language code(s)."))
    if "en" not in {lang.lower() for lang in langs}:
        findings.append(EppRuleFinding("EPP_GREETING_MISSING_EN_LANG", EPP02_ERROR_SEVERITY["EPP_GREETING_MISSING_EN_LANG"], "Greeting languages must include 'en'."))

    obj_uris = [((item.text or "").strip()) for item in _collect_by_local_name(svc_menu, "objURI")]
    for required_uri in required_obj_uris:
        if required_uri not in obj_uris:
            findings.append(EppRuleFinding("EPP_GREETING_MISSING_OBJURI", EPP02_ERROR_SEVERITY["EPP_GREETING_MISSING_OBJURI"], f"Missing required objURI: {required_uri}"))
    if extension_registry_uris is not None:
        for obj_uri in obj_uris:
            if obj_uri not in extension_registry_uris:
                findings.append(EppRuleFinding("EPP_GREETING_UNEXPECTED_OBJURI", EPP02_ERROR_SEVERITY["EPP_GREETING_UNEXPECTED_OBJURI"], f"objURI is not in extension registry: {obj_uri}"))

    ext_uris: list[str] = []
    svc_extension = _find_child_by_local_name(svc_menu, "svcExtension")
    if svc_extension is not None:
        ext_uris = [((item.text or "").strip()) for item in _collect_by_local_name(svc_extension, "extURI")]
    for required_uri in required_ext_uris:
        if required_uri not in ext_uris:
            findings.append(EppRuleFinding("EPP_GREETING_MISSING_EXTURI", EPP02_ERROR_SEVERITY["EPP_GREETING_MISSING_EXTURI"], f"Missing required extURI: {required_uri}"))
    if allow_launch_extension and "urn:ietf:params:xml:ns:launch-1.0" not in ext_uris:
        findings.append(EppRuleFinding("EPP_GREETING_MISSING_EXTURI", EPP02_ERROR_SEVERITY["EPP_GREETING_MISSING_EXTURI"], "Missing required extURI: urn:ietf:params:xml:ns:launch-1.0"))

    missing_recommended = [uri for uri in recommended_ext_uris if uri not in ext_uris]
    if missing_recommended:
        findings.append(EppRuleFinding("EPP_GREETING_RECOMMENDED_EXTENSION_MISSING", EPP02_ERROR_SEVERITY["EPP_GREETING_RECOMMENDED_EXTENSION_MISSING"], f"Missing recommended extensions: {', '.join(missing_recommended)}"))

    if extension_registry_uris is not None:
        for ext_uri in ext_uris:
            if ext_uri not in extension_registry_uris:
                findings.append(EppRuleFinding("EPP_GREETING_UNEXPECTED_EXTURI", EPP02_ERROR_SEVERITY["EPP_GREETING_UNEXPECTED_EXTURI"], f"extURI is not in extension registry: {ext_uri}"))
    return findings


def assess_epp03_login_matrix(attempts: list[EppLoginAttempt]) -> list[EppRuleFinding]:
    findings: list[EppRuleFinding] = []
    for attempt in attempts:
        is_success = EppClient.is_success(attempt.response_xml)
        if attempt.expected_success and not is_success:
            findings.append(EppRuleFinding("EPP_LOGIN_UNEXPECTEDLY_FAILED", EPP03_ERROR_SEVERITY["EPP_LOGIN_UNEXPECTEDLY_FAILED"], f"Scenario '{attempt.scenario}' expected login success but failed."))
        if not attempt.expected_success and is_success:
            findings.append(EppRuleFinding("EPP_LOGIN_UNEXPECTEDLY_SUCCEEDED", EPP03_ERROR_SEVERITY["EPP_LOGIN_UNEXPECTEDLY_SUCCEEDED"], f"Scenario '{attempt.scenario}' expected login rejection but succeeded."))
    return findings


def assess_epp04_domain_check_response(*, response_xml: str, expectation: str) -> list[EppRuleFinding]:
    try:
        code = EppClient.result_code(response_xml)
        root = ET.fromstring(response_xml)
    except (ValueError, ET.ParseError) as exc:
        return [EppRuleFinding("EPP_XML_PARSE_ERROR", EPP04_ERROR_SEVERITY["EPP_XML_PARSE_ERROR"], f"Unable to parse domain check response: {exc}")]

    check_data = root.find(".//{*}chkData")
    name_node = check_data.find(".//{*}name") if check_data is not None else None
    avail = (name_node.attrib.get("avail", "") if name_node is not None else "").strip().lower()
    is_available = avail in {"1", "true"}
    is_unavailable = avail in {"0", "false"}

    if expectation == "invalid":
        if code in {2001, 2004, 2005}:
            return []
        if 1000 <= code < 2000 and is_unavailable:
            return []
        return [EppRuleFinding("EPP_DOMAIN_CHECK_INVALID_DOMAIN_INCORRECT_AVAIL", EPP04_ERROR_SEVERITY["EPP_DOMAIN_CHECK_INVALID_DOMAIN_INCORRECT_AVAIL"], "Invalid domain check must return 2001/2004/2005 or avail=false in a normal response.")]

    if code >= 2000:
        return [EppRuleFinding("EPP_UNEXPECTED_COMMAND_FAILURE", EPP04_ERROR_SEVERITY["EPP_UNEXPECTED_COMMAND_FAILURE"], f"Unexpected command failure for expectation '{expectation}' with code {code}.")]

    if expectation == "registered" and not is_unavailable:
        return [EppRuleFinding("EPP_DOMAIN_CHECK_REGISTERED_DOMAIN_INCORRECT_AVAIL", EPP04_ERROR_SEVERITY["EPP_DOMAIN_CHECK_REGISTERED_DOMAIN_INCORRECT_AVAIL"], "Registered domain must return avail=false.")]
    if expectation == "unregistered" and not is_available:
        return [EppRuleFinding("EPP_DOMAIN_CHECK_VALID_DOMAIN_INCORRECT_AVAIL", EPP04_ERROR_SEVERITY["EPP_DOMAIN_CHECK_VALID_DOMAIN_INCORRECT_AVAIL"], "Unregistered valid domain must return avail=true.")]
    return []


def assess_check_response_semantics(
    *,
    response_xml: str,
    expectation: str,
    object_label: str,
    invalid_allowed_codes: set[int] | None = None,
) -> list[EppRuleFinding]:
    allowed_codes = invalid_allowed_codes or {2001, 2004, 2005}
    try:
        code = EppClient.result_code(response_xml)
        root = ET.fromstring(response_xml)
    except (ValueError, ET.ParseError) as exc:
        return [EppRuleFinding("EPP_XML_PARSE_ERROR", EPP_GENERIC_ERROR_SEVERITY["EPP_XML_PARSE_ERROR"], f"Unable to parse {object_label} check response: {exc}")]

    check_data = root.find(".//{*}chkData")
    name_node = check_data.find(".//{*}name") if check_data is not None else None
    avail = (name_node.attrib.get("avail", "") if name_node is not None else "").strip().lower()
    is_available = avail in {"1", "true"}
    is_unavailable = avail in {"0", "false"}

    if expectation == "invalid":
        if code in allowed_codes:
            return []
        if 1000 <= code < 2000 and is_unavailable:
            return []
        return [EppRuleFinding(f"EPP_{object_label.upper()}_CHECK_INVALID_INCORRECT_AVAIL", "ERROR", f"Invalid {object_label} check must return error {sorted(allowed_codes)} or avail=false.")]

    if code >= 2000:
        return [EppRuleFinding("EPP_UNEXPECTED_COMMAND_FAILURE", EPP_GENERIC_ERROR_SEVERITY["EPP_UNEXPECTED_COMMAND_FAILURE"], f"Unexpected command failure for {object_label} expectation '{expectation}' with code {code}.")]

    if expectation == "registered" and not is_unavailable:
        return [EppRuleFinding(f"EPP_{object_label.upper()}_CHECK_REGISTERED_INCORRECT_AVAIL", "ERROR", f"Registered {object_label} must return avail=false.")]
    if expectation == "unregistered" and not is_available:
        return [EppRuleFinding(f"EPP_{object_label.upper()}_CHECK_VALID_INCORRECT_AVAIL", "ERROR", f"Unregistered {object_label} must return avail=true.")]
    return []


def assess_success_failure_flow(
    *,
    case_label: str,
    success_response_xml: str,
    failure_response_xml: str,
    accepted_failure_codes: set[int] | None = None,
) -> list[EppRuleFinding]:
    findings: list[EppRuleFinding] = []
    try:
        success_ok = EppClient.is_success(success_response_xml)
        failure_code = EppClient.result_code(failure_response_xml)
    except ValueError as exc:
        return [EppRuleFinding("EPP_XML_PARSE_ERROR", EPP_GENERIC_ERROR_SEVERITY["EPP_XML_PARSE_ERROR"], f"{case_label} response parsing failed: {exc}")]

    if not success_ok:
        findings.append(EppRuleFinding("EPP_UNEXPECTED_COMMAND_FAILURE", EPP_GENERIC_ERROR_SEVERITY["EPP_UNEXPECTED_COMMAND_FAILURE"], f"{case_label} happy-path response must succeed."))
    if accepted_failure_codes:
        if failure_code not in accepted_failure_codes:
            findings.append(EppRuleFinding("EPP_UNEXPECTED_COMMAND_SUCCESS", EPP_GENERIC_ERROR_SEVERITY["EPP_UNEXPECTED_COMMAND_SUCCESS"], f"{case_label} negative-path code must be in {sorted(accepted_failure_codes)}."))
    elif 1000 <= failure_code < 2000:
        findings.append(EppRuleFinding("EPP_UNEXPECTED_COMMAND_SUCCESS", EPP_GENERIC_ERROR_SEVERITY["EPP_UNEXPECTED_COMMAND_SUCCESS"], f"{case_label} negative-path response must fail."))
    return findings
