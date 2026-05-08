from __future__ import annotations

from pathlib import Path
from typing import Any
import socket
import ssl
import struct
from unittest.mock import Mock

import pytest

from rst_compliance.epp_client import EppClient, EppMtlsConfig, EppTlsHandshakeError, SocketEppTransport


EPP_SUCCESS_RESPONSE = '<epp><response><result code="1000"><msg>Command completed successfully</msg></result></response></epp>'
EPP_POLICY_ERROR_RESPONSE = '<epp><response><result code="2306"><msg>Parameter value policy error</msg></result></response></epp>'


class _FakeTransport:
    def __init__(self, responses: list[str]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def send(self, *, xml_command: str, host: str, port: int, timeout_seconds: int, **_: Any) -> str:
        self.calls.append(
            {
                "xml_command": xml_command,
                "host": host,
                "port": port,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.responses.pop(0)


def _config(base_dir: Path) -> EppMtlsConfig:
    return EppMtlsConfig(
        host="epp.example.test",
        client_cert_file=base_dir / "cert.pem",
        client_key_file=base_dir / "key.pem",
        key_algorithm="RSA",
        key_size_bits=4096,
    )


def test_epp26_blocks_internal_host_glue_creation(tmp_path: Path) -> None:
    transport = _FakeTransport(responses=[EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    create_host_with_glue = """
    <epp>
      <command>
        <create>
          <host:create xmlns:host='urn:ietf:params:xml:ns:host-1.0'>
            <host:name>ns1.other-client.example.test</host:name>
            <host:addr ip='v4'>192.0.2.44</host:addr>
          </host:create>
        </create>
      </command>
    </epp>
    """

    response = client.send_command(create_host_with_glue)

    assert client.is_success(response) is False
    assert EppClient.result_code(response) == 2306


def test_epp27_blocks_glueless_internal_host_delegation(tmp_path: Path) -> None:
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    create_glueless_internal_host = """
    <epp>
      <command>
        <create>
          <host:create xmlns:host='urn:ietf:params:xml:ns:host-1.0'>
            <host:name>ns2.other-client.example.test</host:name>
          </host:create>
        </create>
      </command>
    </epp>
    """
    add_host_to_domain = """
    <epp>
      <command>
        <update>
          <domain:update xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'>
            <domain:name>other-client.example.test</domain:name>
            <domain:add>
              <domain:ns>
                <domain:hostObj>ns2.other-client.example.test</domain:hostObj>
              </domain:ns>
            </domain:add>
          </domain:update>
        </update>
      </command>
    </epp>
    """

    create_response = client.send_command(create_glueless_internal_host)
    update_response = client.send_command(add_host_to_domain)

    assert client.is_success(create_response) is True
    assert client.is_success(update_response) is False
    assert EppClient.result_code(update_response) == 2306


def test_epp_client_requires_rsa_4096_mtls_keys(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="4096-bit"):
        EppMtlsConfig(
            host="epp.example.test",
            client_cert_file=tmp_path / "cert.pem",
            client_key_file=tmp_path / "key.pem",
            key_algorithm="RSA",
            key_size_bits=2048,
        )


def test_epp_client_accepts_ecdsa_p256_mtls_keys(tmp_path: Path) -> None:
    config = EppMtlsConfig(
        host="epp.example.test",
        client_cert_file=tmp_path / "cert.pem",
        client_key_file=tmp_path / "key.pem",
        key_algorithm="ECDSA",
        key_size_bits=256,
    )

    assert config.key_algorithm == "ECDSA"
    assert config.key_size_bits == 256


class _FakeSocket:
    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, *_: Any) -> bool:
        return False


class _FakeTlsSocket(_FakeSocket):
    def __init__(self, responses: list[bytes]) -> None:
        self.responses = responses
        self.sent_payload = b""

    def sendall(self, payload: bytes) -> None:
        self.sent_payload = payload

    def recv(self, size: int) -> bytes:
        if not self.responses:
            return b""
        current = self.responses[0]
        chunk = current[:size]
        remaining = current[size:]
        if remaining:
            self.responses[0] = remaining
        else:
            self.responses.pop(0)
        return chunk


def test_run_login_and_check_reports_pass_for_basic_commands(tmp_path: Path) -> None:
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_SUCCESS_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    results = client.run_login_and_check(login_xml="<epp><command><login/></command></epp>", check_xml="<epp><command><check/></command></epp>")

    assert [result.command_name for result in results] == ["login", "check"]
    assert all(result.status == "pass" for result in results)


def test_run_login_and_check_flags_narrow_glue_policy_violation(tmp_path: Path) -> None:
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    results = client.run_login_and_check(login_xml="<epp><command><login/></command></epp>", check_xml="<epp><command><check/></command></epp>")

    assert results[0].status == "pass"
    assert results[1].status == "fail"
    assert "Narrow Glue Policy" in results[1].reason


def test_socket_transport_uses_rfc5734_length_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    xml_command = "<epp><command><hello/></command></epp>"
    response_xml = "<epp><response><result code='1000'/></response></epp>"
    framed_response = struct.pack("!I", len(response_xml.encode("utf-8")) + 4) + response_xml.encode("utf-8")
    fake_tls_socket = _FakeTlsSocket(responses=[framed_response])
    fake_ssl_context = Mock(name="ssl_context")
    fake_ssl_context.wrap_socket.return_value = fake_tls_socket

    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: _FakeSocket())
    transport = SocketEppTransport()

    response = transport.send(
        xml_command=xml_command,
        ssl_context=fake_ssl_context,
        host="epp.example.test",
        port=700,
        timeout_seconds=30,
    )

    expected_sent_frame = struct.pack("!I", len(xml_command.encode("utf-8")) + 4) + xml_command.encode("utf-8")
    assert fake_tls_socket.sent_payload == expected_sent_frame
    assert response == response_xml
    fake_ssl_context.wrap_socket.assert_called_once()


def test_socket_transport_wraps_certificate_verification_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ssl_context = Mock(name="ssl_context")
    fake_ssl_context.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate has expired")
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: _FakeSocket())
    transport = SocketEppTransport()

    with pytest.raises(EppTlsHandshakeError, match="certificate verification error"):
        transport.send(
            xml_command="<epp><command><hello/></command></epp>",
            ssl_context=fake_ssl_context,
            host="epp.example.test",
            port=700,
            timeout_seconds=30,
        )


def test_socket_transport_wraps_zero_return_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_ssl_context = Mock(name="ssl_context")
    fake_ssl_context.wrap_socket.side_effect = ssl.SSLZeroReturnError(1, "TLS/SSL connection has been closed")
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: _FakeSocket())
    transport = SocketEppTransport()

    with pytest.raises(EppTlsHandshakeError, match="possible cipher suite mismatch"):
        transport.send(
            xml_command="<epp><command><hello/></command></epp>",
            ssl_context=fake_ssl_context,
            host="epp.example.test",
            port=700,
            timeout_seconds=30,
        )
