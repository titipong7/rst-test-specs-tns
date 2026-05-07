"""
RDAP TLS tests – RST 2.0 compliance.

Maps to RST test cases rdap-91 (TLS conformance) from inc/rdap/cases.yaml.
These tests are marked as slow because they perform real TLS handshakes.
"""

from __future__ import annotations

import logging
import socket
import ssl

import pytest

from tests.rdap.conftest import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.rdap, pytest.mark.slow]

# Minimum acceptable TLS version per RST spec (rdap-91)
REQUIRED_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def _get_host_port(base_url: str) -> tuple[str, int]:
    """Extract host and port from an RDAP base URL."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or 443
    return host, port


class TestRDAPTLSConformance:
    """rdap-91 – TLS version conformance check."""

    def test_tls_connection_succeeds(
        self,
        rdap_base_urls: list[dict],
    ) -> None:
        """Server MUST accept a TLS 1.2+ connection."""
        for entry in rdap_base_urls:
            host, port = _get_host_port(entry["baseURL"])
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            try:
                with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT[0]) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as tls:
                        version = tls.version()
                        logger.info(
                            "TLS connection to %s:%d – negotiated %s", host, port, version
                        )
                        assert version in ("TLSv1.2", "TLSv1.3"), (
                            f"rdap-91: Expected TLS 1.2 or 1.3, got {version}"
                        )
            except ssl.SSLError as exc:
                pytest.fail(f"rdap-91: RDAP_TLS_SERVICE_PORT_UNREACHABLE – {exc}")
            except OSError as exc:
                pytest.fail(f"rdap-91: RDAP_TLS_DNS_RESOLUTION_ERROR – {exc}")

    def test_certificate_not_expired(
        self,
        rdap_base_urls: list[dict],
    ) -> None:
        """Server certificate MUST NOT be expired."""
        for entry in rdap_base_urls:
            host, port = _get_host_port(entry["baseURL"])
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            try:
                with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT[0]) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        assert cert, (
                            f"rdap-91: RDAP_TLS_UNTRUSTED_CERTIFICATE – no cert returned"
                        )
            except ssl.CertificateError as exc:
                pytest.fail(
                    f"rdap-91: RDAP_TLS_CERTIFICATE_HOSTNAME_MISMATCH – {exc}"
                )
            except ssl.SSLError as exc:
                pytest.fail(f"rdap-91: RDAP_TLS_EXPIRED_CERTIFICATE or untrusted CA – {exc}")
            except OSError as exc:
                pytest.fail(f"rdap-91: RDAP_TLS_SERVICE_PORT_UNREACHABLE – {exc}")
