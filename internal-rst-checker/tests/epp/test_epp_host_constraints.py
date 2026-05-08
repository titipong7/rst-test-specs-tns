from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from rst_compliance.epp_client import EppClient, EppMtlsConfig


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
