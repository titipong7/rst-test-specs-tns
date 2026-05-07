"""
EPP conftest – provides a reusable EPP TCP/TLS client session fixture.

The ``epp_client`` fixture yields a connected, authenticated
:class:`EPPClient` instance for the duration of the test module.  All EPP
XML payloads are sent and received as raw bytes; the caller is responsible for
parsing the response with ``lxml``.

Environment / config keys (``epp`` section of ``resources/config.yaml``):
  host        : EPP server hostname            (required)
  port        : EPP server port (default 700)  (optional)
  clid        : Client ID / username           (required)
  pwd         : Password                       (required)
  tls_cert    : Path to PEM client certificate (optional)
  tls_key     : Path to PEM client key         (optional)
"""

from __future__ import annotations

import socket
import ssl
import struct
import logging
from typing import Optional

import pytest
from lxml import etree

logger = logging.getLogger(__name__)

EPP_NS = "urn:ietf:params:xml:ns:epp-1.0"
EPP_HEADER_LEN = 4  # 32-bit big-endian total frame length


class EPPClient:
    """Minimal synchronous EPP client over TCP/TLS (RFC 5734)."""

    def __init__(self, host: str, port: int, ssl_context: ssl.SSLContext) -> None:
        self._host = host
        self._port = port
        self._ctx = ssl_context
        self._sock: Optional[ssl.SSLSocket] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> etree._Element:
        """Open the TCP/TLS connection and read the server greeting."""
        raw_sock = socket.create_connection((self._host, self._port), timeout=30)
        self._sock = self._ctx.wrap_socket(raw_sock, server_hostname=self._host)
        logger.info("Connected to %s:%d", self._host, self._port)
        greeting_bytes = self._read_frame()
        return etree.fromstring(greeting_bytes)

    def disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Frame I/O (RFC 5734 §4)
    # ------------------------------------------------------------------

    def _read_frame(self) -> bytes:
        header = self._recv_exact(EPP_HEADER_LEN)
        total_length = struct.unpack("!I", header)[0]
        payload_length = total_length - EPP_HEADER_LEN
        return self._recv_exact(payload_length)

    def _send_frame(self, payload: bytes) -> None:
        total_length = len(payload) + EPP_HEADER_LEN
        header = struct.pack("!I", total_length)
        self._sock.sendall(header + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EPP server closed connection unexpectedly")
            buf += chunk
        return buf

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def send_command(self, xml_bytes: bytes) -> etree._Element:
        """Send an EPP command and return the parsed XML response."""
        self._send_frame(xml_bytes)
        response_bytes = self._read_frame()
        return etree.fromstring(response_bytes)

    def login(self, clid: str, pwd: str) -> etree._Element:
        """Send an EPP <login> command."""
        payload = (
            f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            f'<epp xmlns="{EPP_NS}">'
            f"  <command>"
            f"    <login>"
            f"      <clID>{clid}</clID>"
            f"      <pw>{pwd}</pw>"
            f"      <options><version>1.0</version><lang>en</lang></options>"
            f"      <svcs>"
            f'        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>'
            f'        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>'
            f'        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>'
            f"      </svcs>"
            f"    </login>"
            f"  </command>"
            f"</epp>"
        ).encode()
        return self.send_command(payload)

    def logout(self) -> etree._Element:
        """Send an EPP <logout> command."""
        payload = (
            f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            f'<epp xmlns="{EPP_NS}">'
            f"  <command><logout/></command>"
            f"</epp>"
        ).encode()
        return self.send_command(payload)

    @staticmethod
    def result_code(response: etree._Element) -> int:
        """Extract the numeric result code from an EPP response element."""
        ns = {"epp": EPP_NS}
        result = response.find(".//epp:result", ns)
        if result is None:
            raise ValueError("No <result> element found in EPP response")
        return int(result.get("code", "0"))


# ------------------------------------------------------------------
# Pytest fixtures
# ------------------------------------------------------------------


def _build_ssl_context(cfg: dict) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    cert = cfg.get("tls_cert")
    key = cfg.get("tls_key")
    if cert:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


@pytest.fixture(scope="module")
def epp_client(epp_config):
    """
    Yield a connected, logged-in EPPClient.  The session is torn down after
    the test module finishes.
    """
    host = epp_config.get("host")
    if not host:
        pytest.skip("EPP host not configured – skipping EPP tests")

    port = int(epp_config.get("port", 700))
    clid = epp_config["clid"]
    pwd = epp_config["pwd"]

    ctx = _build_ssl_context(epp_config)
    client = EPPClient(host, port, ctx)

    greeting = client.connect()
    logger.info("Received EPP greeting from %s", host)

    login_response = client.login(clid, pwd)
    code = EPPClient.result_code(login_response)
    assert code == 1000, f"EPP login failed with result code {code}"
    logger.info("EPP login successful (code=%d)", code)

    yield client

    try:
        client.logout()
    finally:
        client.disconnect()
