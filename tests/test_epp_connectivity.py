from __future__ import annotations

from rst_compliance.epp_connectivity import Epp01ProbeConfig, ServicePortProbe, run_epp01_connectivity_probe


def test_epp01_marks_dns_resolution_error() -> None:
    def _resolve_dns(_: str) -> tuple[list[str], list[str]]:
        raise OSError("lookup failed")

    result = run_epp01_connectivity_probe(Epp01ProbeConfig(host="epp.example.test"), resolve_dns=_resolve_dns)
    codes = {item.code for item in result.findings}
    assert "EPP_DNS_RESOLUTION_ERROR" in codes
    assert result.overall_status() == "fail"


def test_epp01_marks_missing_aaaa_and_unreachable_port() -> None:
    def _resolve_dns(_: str) -> tuple[list[str], list[str]]:
        return (["192.0.2.10"], [])

    def _probe(ip: str, *_: object) -> ServicePortProbe:
        return ServicePortProbe(ip=ip, tcp_reachable=False, tls12_supported=False, tls11_supported=False)

    result = run_epp01_connectivity_probe(Epp01ProbeConfig(host="epp.example.test"), resolve_dns=_resolve_dns, probe_port=_probe)
    codes = {item.code for item in result.findings}
    assert "EPP_MISSING_AAAA_RECORDS" in codes
    assert "EPP_NO_SERVICE_PORTS_REACHABLE" in codes
    assert "EPP_SERVICE_PORT_UNREACHABLE" in codes


def test_epp01_enforces_tls_and_certificate_and_cipher_rules() -> None:
    def _resolve_dns(_: str) -> tuple[list[str], list[str]]:
        return (["192.0.2.20"], ["2001:db8::20"])

    def _probe(ip: str, *_: object) -> ServicePortProbe:
        if ":" in ip:
            return ServicePortProbe(
                ip=ip,
                tcp_reachable=True,
                tls12_supported=True,
                tls11_supported=False,
                peer_cipher="TLS_AES_256_GCM_SHA384",
                cert_trusted=True,
                cert_expired=False,
                cert_chain_complete=True,
                cert_hostname_matches=True,
            )
        return ServicePortProbe(
            ip=ip,
            tcp_reachable=True,
            tls12_supported=False,
            tls11_supported=True,
            tls_error="certificate verify failed: unable to get local issuer certificate",
            peer_cipher="AES256-SHA",
            cert_trusted=False,
            cert_expired=True,
            cert_chain_complete=False,
            cert_hostname_matches=False,
        )

    result = run_epp01_connectivity_probe(Epp01ProbeConfig(host="epp.example.test"), resolve_dns=_resolve_dns, probe_port=_probe)
    codes = {item.code for item in result.findings}
    assert "EPP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED" in codes
    assert "EPP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED" in codes
    assert "EPP_TLS_CONNECTION_ERROR" in codes
    assert "EPP_TLS_UNTRUSTED_CERTIFICATE" in codes
    assert "EPP_TLS_EXPIRED_CERTIFICATE" in codes
    assert "EPP_TLS_CERTIFICATE_CHAIN_MISSING" in codes
    assert "EPP_TLS_CERTIFICATE_HOSTNAME_MISMATCH" in codes
    assert "EPP_TLS_BAD_CIPHER" in codes
    assert result.to_dict()["status"] == "fail"


def test_epp01_passes_when_all_rules_are_met() -> None:
    def _resolve_dns(_: str) -> tuple[list[str], list[str]]:
        return (["192.0.2.30"], ["2001:db8::30"])

    def _probe(ip: str, *_: object) -> ServicePortProbe:
        return ServicePortProbe(
            ip=ip,
            tcp_reachable=True,
            tls12_supported=True,
            tls11_supported=False,
            peer_cipher="TLS_AES_128_GCM_SHA256",
            cert_trusted=True,
            cert_expired=False,
            cert_chain_complete=True,
            cert_hostname_matches=True,
        )

    result = run_epp01_connectivity_probe(Epp01ProbeConfig(host="epp.example.test"), resolve_dns=_resolve_dns, probe_port=_probe)
    assert result.findings == []
    assert result.overall_status() == "pass"
