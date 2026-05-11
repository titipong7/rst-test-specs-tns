from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from datetime import datetime

from rst_compliance.epp_client import (
    EppClient,
    EppLoginAttempt,
    EppMtlsConfig,
    assess_check_response_semantics,
    assess_epp02_greeting,
    assess_epp03_login_matrix,
    assess_epp04_domain_check_response,
    assess_success_failure_flow,
)
from rst_compliance.epp_connectivity import EPP01_ERROR_SEVERITY


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


def test_validate_extension_xml_requires_extension_root_and_child_elements() -> None:
    valid_extension = (
        "<extension xmlns='urn:ietf:params:xml:ns:epp-1.0'>"
        "<login xmlns='our:epp:extension'><flag>1</flag></login>"
        "</extension>"
    )
    EppClient.validate_extension_xml(valid_extension)

    with pytest.raises(ValueError, match="<extension>"):
        EppClient.validate_extension_xml("<login/>")

    with pytest.raises(ValueError, match="at least one child"):
        EppClient.validate_extension_xml("<extension xmlns='urn:ietf:params:xml:ns:epp-1.0'></extension>")


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


def test_epp01_error_code_mapping_includes_dns_tls_and_cipher_categories() -> None:
    assert EPP01_ERROR_SEVERITY["EPP_DNS_RESOLUTION_ERROR"] == "CRITICAL"
    assert EPP01_ERROR_SEVERITY["EPP_MISSING_AAAA_RECORDS"] == "WARNING"
    assert EPP01_ERROR_SEVERITY["EPP_TLS_REQUIRED_PROTOCOL_NOT_SUPPORTED"] == "ERROR"
    assert EPP01_ERROR_SEVERITY["EPP_TLS_BAD_CIPHER"] == "ERROR"


def test_epp02_greeting_rules_detect_required_field_issues() -> None:
    greeting = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><greeting>"
        "<svID>wrong-server</svID>"
        "<svDate>2026-05-11T08:00:00Z</svDate>"
        "<svcMenu><version>2.0</version><lang>th-TH</lang></svcMenu>"
        "</greeting></epp>"
    )
    findings = assess_epp02_greeting(
        greeting,
        expected_server_id="expected-server",
        now_utc=datetime.fromisoformat("2026-05-11T09:00:00+00:00"),
        extension_registry_uris={"urn:ietf:params:xml:ns:domain-1.0"},
    )
    codes = {item.code for item in findings}
    assert "EPP_GREETING_SVID_INVALID" in codes
    assert "EPP_GREETING_SVDATE_INVALID" in codes
    assert "EPP_GREETING_VERSION_INVALID" in codes
    assert "EPP_GREETING_MISSING_EN_LANG" in codes
    assert "EPP_GREETING_MISSING_OBJURI" in codes
    assert "EPP_GREETING_MISSING_EXTURI" in codes


def test_epp02_greeting_records_warning_for_missing_recommended_extension() -> None:
    greeting = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><greeting>"
        "<svID>ok-server</svID><svDate>2026-05-11T09:00:00Z</svDate><svcMenu>"
        "<version>1.0</version><lang>en</lang>"
        "<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>"
        "<svcExtension><extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI><extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI><extURI>urn:ietf:params:xml:ns:launch-1.0</extURI></svcExtension>"
        "</svcMenu></greeting></epp>"
    )
    findings = assess_epp02_greeting(
        greeting,
        expected_server_id="ok-server",
        now_utc=datetime.fromisoformat("2026-05-11T09:00:05+00:00"),
        extension_registry_uris={
            "urn:ietf:params:xml:ns:domain-1.0",
            "urn:ietf:params:xml:ns:secDNS-1.1",
            "urn:ietf:params:xml:ns:rgp-1.0",
            "urn:ietf:params:xml:ns:launch-1.0",
        },
    )
    assert len(findings) == 1
    assert findings[0].code == "EPP_GREETING_RECOMMENDED_EXTENSION_MISSING"
    assert findings[0].severity == "WARNING"


def test_epp03_login_matrix_returns_expected_findings() -> None:
    findings = assess_epp03_login_matrix(
        [
            EppLoginAttempt("invalid-client-id", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
            EppLoginAttempt("valid-credentials", expected_success=True, response_xml=EPP_SUCCESS_RESPONSE),
            EppLoginAttempt("unexpected-success", expected_success=False, response_xml=EPP_SUCCESS_RESPONSE),
            EppLoginAttempt("unexpected-failure", expected_success=True, response_xml=EPP_POLICY_ERROR_RESPONSE),
        ]
    )
    codes = [item.code for item in findings]
    assert "EPP_LOGIN_UNEXPECTEDLY_SUCCEEDED" in codes
    assert "EPP_LOGIN_UNEXPECTEDLY_FAILED" in codes


def test_epp04_domain_check_response_paths() -> None:
    invalid_allowed = "<epp><response><result code='2005'/></response></epp>"
    invalid_bad = "<epp><response><result code='1000'/><resData><domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'><domain:cd><domain:name avail='1'>invalid domain</domain:name></domain:cd></domain:chkData></resData></response></epp>"
    registered_bad = "<epp><response><result code='1000'/><resData><domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'><domain:cd><domain:name avail='true'>taken.example</domain:name></domain:cd></domain:chkData></resData></response></epp>"
    unregistered_bad = "<epp><response><result code='1000'/><resData><domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'><domain:cd><domain:name avail='0'>open.example</domain:name></domain:cd></domain:chkData></resData></response></epp>"

    assert assess_epp04_domain_check_response(response_xml=invalid_allowed, expectation="invalid") == []
    assert assess_epp04_domain_check_response(response_xml=invalid_bad, expectation="invalid")[0].code == "EPP_DOMAIN_CHECK_INVALID_DOMAIN_INCORRECT_AVAIL"
    assert assess_epp04_domain_check_response(response_xml=registered_bad, expectation="registered")[0].code == "EPP_DOMAIN_CHECK_REGISTERED_DOMAIN_INCORRECT_AVAIL"
    assert assess_epp04_domain_check_response(response_xml=unregistered_bad, expectation="unregistered")[0].code == "EPP_DOMAIN_CHECK_VALID_DOMAIN_INCORRECT_AVAIL"


def test_generic_check_response_semantics_for_host_contact() -> None:
    host_registered = "<epp><response><result code='1000'/><resData><chkData><cd><name avail='false'>ns1</name></cd></chkData></resData></response></epp>"
    contact_unregistered = "<epp><response><result code='1000'/><resData><chkData><cd><name avail='1'>new-contact</name></cd></chkData></resData></response></epp>"
    invalid_error = "<epp><response><result code='2004'/></response></epp>"
    assert assess_check_response_semantics(response_xml=host_registered, expectation="registered", object_label="host") == []
    assert assess_check_response_semantics(response_xml=contact_unregistered, expectation="unregistered", object_label="contact") == []
    assert assess_check_response_semantics(response_xml=invalid_error, expectation="invalid", object_label="host") == []


def test_success_failure_flow_catches_unexpected_success_and_failure() -> None:
    ok = "<epp><response><result code='1000'/></response></epp>"
    fail = "<epp><response><result code='2306'/></response></epp>"
    assert assess_success_failure_flow(case_label="epp-x", success_response_xml=ok, failure_response_xml=fail) == []
    unexpected = assess_success_failure_flow(case_label="epp-x", success_response_xml=fail, failure_response_xml=ok)
    codes = {item.code for item in unexpected}
    assert "EPP_UNEXPECTED_COMMAND_FAILURE" in codes
    assert "EPP_UNEXPECTED_COMMAND_SUCCESS" in codes
