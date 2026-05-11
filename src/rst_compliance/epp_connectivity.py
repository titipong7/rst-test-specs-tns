from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import socket
import ssl
from typing import Callable


RECOMMENDED_CIPHERS_RFC9325 = frozenset(
    {
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
    }
)

EPP01_ERROR_SEVERITY = {
    "EPP_DNS_RESOLUTION_ERROR": "CRITICAL",
    "EPP_MISSING_A_RECORDS": "CRITICAL",
    "EPP_MISSING_AAAA_RECORDS": "WARNING",
    "EPP_NO_SERVICE_PORTS_REACHABLE": "CRITICAL",
    "EPP_SERVICE_PORT_UNREACHABLE": "WARNING",
    "EPP_TLS_CONNECTION_ERROR": "ERROR",
    "EPP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED": "ERROR",
    "EPP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED": "ERROR",
    "EPP_TLS_UNTRUSTED_CERTIFICATE": "ERROR",
    "EPP_TLS_EXPIRED_CERTIFICATE": "ERROR",
    "EPP_TLS_CERTIFICATE_CHAIN_MISSING": "ERROR",
    "EPP_TLS_CERTIFICATE_HOSTNAME_MISMATCH": "ERROR",
    "EPP_TLS_BAD_CIPHER": "ERROR",
}


@dataclass(frozen=True)
class Epp01ProbeConfig:
    host: str
    port: int = 700
    timeout_seconds: int = 5
    recommended_ciphers: frozenset[str] = RECOMMENDED_CIPHERS_RFC9325


@dataclass(frozen=True)
class ServicePortProbe:
    ip: str
    tcp_reachable: bool
    tls12_supported: bool
    tls11_supported: bool
    tls_error: str | None = None
    peer_cipher: str | None = None
    cert_trusted: bool = False
    cert_expired: bool = False
    cert_chain_complete: bool = True
    cert_hostname_matches: bool = True


@dataclass(frozen=True)
class Epp01Finding:
    code: str
    severity: str
    message: str
    target: str | None = None


@dataclass
class Epp01ProbeResult:
    host: str
    port: int
    dns_a_records: list[str] = field(default_factory=list)
    dns_aaaa_records: list[str] = field(default_factory=list)
    service_ports: list[ServicePortProbe] = field(default_factory=list)
    findings: list[Epp01Finding] = field(default_factory=list)

    def overall_status(self) -> str:
        if any(item.severity in {"CRITICAL", "ERROR"} for item in self.findings):
            return "fail"
        return "pass"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "dns": {
                "a_records": self.dns_a_records,
                "aaaa_records": self.dns_aaaa_records,
            },
            "servicePorts": [
                {
                    "ip": item.ip,
                    "tcpReachable": item.tcp_reachable,
                    "tls12Supported": item.tls12_supported,
                    "tls11Supported": item.tls11_supported,
                    "tlsError": item.tls_error,
                    "peerCipher": item.peer_cipher,
                    "certTrusted": item.cert_trusted,
                    "certExpired": item.cert_expired,
                    "certChainComplete": item.cert_chain_complete,
                    "certHostnameMatches": item.cert_hostname_matches,
                }
                for item in self.service_ports
            ],
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity,
                    "message": finding.message,
                    "target": finding.target,
                }
                for finding in self.findings
            ],
            "status": self.overall_status(),
        }


ResolveDnsFn = Callable[[str], tuple[list[str], list[str]]]
ProbePortFn = Callable[[str, int, str, int], ServicePortProbe]


def _default_resolve_dns(host: str) -> tuple[list[str], list[str]]:
    records = socket.getaddrinfo(host, None)
    a_records: set[str] = set()
    aaaa_records: set[str] = set()
    for family, _, _, _, sockaddr in records:
        ip = sockaddr[0]
        if family == socket.AF_INET:
            a_records.add(ip)
        elif family == socket.AF_INET6:
            aaaa_records.add(ip)
    return sorted(a_records), sorted(aaaa_records)


def _is_expired_cert(not_after: str | None) -> bool:
    if not not_after:
        return True
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc)
    except ValueError:
        return True


def _probe_tls_protocol(ip: str, port: int, host: str, timeout_seconds: int, version: ssl.TLSVersion) -> tuple[bool, str | None, dict | None, str | None]:
    context = ssl.create_default_context()
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as tcp_sock:
            with context.wrap_socket(tcp_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()[0] if tls_sock.cipher() else None
                return True, None, cert, cipher
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc), None, None


def _default_probe_port(ip: str, port: int, host: str, timeout_seconds: int) -> ServicePortProbe:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds):
            tcp_reachable = True
    except OSError:
        return ServicePortProbe(ip=ip, tcp_reachable=False, tls12_supported=False, tls11_supported=False)

    tls12_supported, tls12_error, cert, cipher = _probe_tls_protocol(
        ip=ip,
        port=port,
        host=host,
        timeout_seconds=timeout_seconds,
        version=ssl.TLSVersion.TLSv1_2,
    )
    tls11_supported, tls11_error, _, _ = _probe_tls_protocol(
        ip=ip,
        port=port,
        host=host,
        timeout_seconds=timeout_seconds,
        version=ssl.TLSVersion.TLSv1_1,
    )

    cert_trusted = tls12_supported
    cert_expired = _is_expired_cert(cert.get("notAfter") if cert else None)
    cert_chain_complete = True
    cert_hostname_matches = True
    tls_error = tls12_error

    if tls12_error:
        low = tls12_error.lower()
        if "self signed" in low:
            cert_trusted = False
        if "hostname" in low:
            cert_hostname_matches = False
        if "unable to get local issuer" in low or "certificate chain" in low:
            cert_chain_complete = False
    if not tls11_supported and tls11_error and "unsupported protocol" in tls11_error.lower():
        pass

    return ServicePortProbe(
        ip=ip,
        tcp_reachable=tcp_reachable,
        tls12_supported=tls12_supported,
        tls11_supported=tls11_supported,
        tls_error=tls_error,
        peer_cipher=cipher,
        cert_trusted=cert_trusted,
        cert_expired=cert_expired,
        cert_chain_complete=cert_chain_complete,
        cert_hostname_matches=cert_hostname_matches,
    )


def _add_finding(result: Epp01ProbeResult, code: str, message: str, target: str | None = None) -> None:
    result.findings.append(
        Epp01Finding(code=code, severity=EPP01_ERROR_SEVERITY[code], message=message, target=target)
    )


def run_epp01_connectivity_probe(
    config: Epp01ProbeConfig,
    *,
    resolve_dns: ResolveDnsFn = _default_resolve_dns,
    probe_port: ProbePortFn = _default_probe_port,
) -> Epp01ProbeResult:
    result = Epp01ProbeResult(host=config.host, port=config.port)
    try:
        a_records, aaaa_records = resolve_dns(config.host)
    except OSError as exc:
        _add_finding(result, "EPP_DNS_RESOLUTION_ERROR", f"DNS resolution failed: {exc}")
        return result

    result.dns_a_records = a_records
    result.dns_aaaa_records = aaaa_records
    if not a_records:
        _add_finding(result, "EPP_MISSING_A_RECORDS", "No A records were resolved for EPP host.")
    if not aaaa_records:
        _add_finding(result, "EPP_MISSING_AAAA_RECORDS", "No AAAA records were resolved for EPP host.")

    for ip in a_records + aaaa_records:
        result.service_ports.append(probe_port(ip, config.port, config.host, config.timeout_seconds))

    reachable = [item for item in result.service_ports if item.tcp_reachable]
    if not reachable:
        _add_finding(result, "EPP_NO_SERVICE_PORTS_REACHABLE", "No service ports were reachable on TCP/700.")

    for item in result.service_ports:
        if not item.tcp_reachable:
            _add_finding(result, "EPP_SERVICE_PORT_UNREACHABLE", "Service port unreachable on TCP/700.", target=item.ip)
            continue
        if not item.tls12_supported:
            _add_finding(result, "EPP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED", "TLSv1.2 handshake failed.", target=item.ip)
        if item.tls11_supported:
            _add_finding(result, "EPP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED", "TLSv1.1 is supported but forbidden.", target=item.ip)
        if item.tls_error:
            _add_finding(result, "EPP_TLS_CONNECTION_ERROR", f"TLS connection error: {item.tls_error}", target=item.ip)
        if not item.cert_trusted:
            _add_finding(result, "EPP_TLS_UNTRUSTED_CERTIFICATE", "TLS certificate is not trusted by default trust store.", target=item.ip)
        if item.cert_expired:
            _add_finding(result, "EPP_TLS_EXPIRED_CERTIFICATE", "TLS certificate is expired or expiry is not parseable.", target=item.ip)
        if not item.cert_chain_complete:
            _add_finding(result, "EPP_TLS_CERTIFICATE_CHAIN_MISSING", "TLS certificate chain appears incomplete.", target=item.ip)
        if not item.cert_hostname_matches:
            _add_finding(result, "EPP_TLS_CERTIFICATE_HOSTNAME_MISMATCH", "Certificate hostname validation failed.", target=item.ip)
        if item.peer_cipher and item.peer_cipher not in config.recommended_ciphers:
            _add_finding(result, "EPP_TLS_BAD_CIPHER", f"Negotiated cipher '{item.peer_cipher}' is not in recommended RFC 9325 set.", target=item.ip)

    return result
