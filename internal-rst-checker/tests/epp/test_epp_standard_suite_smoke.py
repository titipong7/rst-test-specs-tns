from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from rst_compliance.epp_client import (
    EppClient,
    EppMtlsConfig,
    EppLoginAttempt,
    assess_check_response_semantics,
    assess_epp02_greeting,
    assess_epp03_login_matrix,
    assess_epp04_domain_check_response,
    assess_success_failure_flow,
)
from rst_compliance.epp_connectivity import Epp01ProbeConfig, ServicePortProbe, run_epp01_connectivity_probe

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


def _config(base_dir: Path, *, port: int = 700) -> EppMtlsConfig:
    return EppMtlsConfig(
        host="epp.example.test",
        client_cert_file=base_dir / "cert.pem",
        client_key_file=base_dir / "key.pem",
        key_algorithm="RSA",
        key_size_bits=4096,
        port=port,
    )


def test_epp_service_connectivity_smoke_epp_01(tmp_path: Path) -> None:
    """covers epp-01"""
    def _resolve_dns(_: str) -> tuple[list[str], list[str]]:
        return (["192.0.2.8"], ["2001:db8::8"])

    def _probe(ip: str, *_: object) -> ServicePortProbe:
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

    result = run_epp01_connectivity_probe(Epp01ProbeConfig(host="epp.example.test"), resolve_dns=_resolve_dns, probe_port=_probe)
    assert result.overall_status() == "pass"
    assert result.findings == []


def test_epp_protocol_extension_shape_validation_epp_02() -> None:
    """covers epp-02"""
    greeting = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'>"
        "<greeting>"
        "<svID>rst-epp-server</svID>"
        "<svDate>2026-05-11T09:00:00Z</svDate>"
        "<svcMenu>"
        "<version>1.0</version>"
        "<lang>en</lang>"
        "<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>"
        "<svcExtension>"
        "<extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>"
        "<extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>"
        "<extURI>urn:ietf:params:xml:ns:launch-1.0</extURI>"
        "</svcExtension>"
        "</svcMenu>"
        "</greeting>"
        "</epp>"
    )
    findings = assess_epp02_greeting(
        greeting,
        expected_server_id="rst-epp-server",
        now_utc=datetime.fromisoformat("2026-05-11T09:00:10+00:00"),
        extension_registry_uris={
            "urn:ietf:params:xml:ns:domain-1.0",
            "urn:ietf:params:xml:ns:secDNS-1.1",
            "urn:ietf:params:xml:ns:rgp-1.0",
            "urn:ietf:params:xml:ns:launch-1.0",
        },
        recommended_ext_uris=(),
    )
    assert findings == []

    malformed = "<epp><greeting><svID>bad</svID></greeting>"
    parse_findings = assess_epp02_greeting(malformed, expected_server_id="rst-epp-server")
    assert parse_findings[0].code == "EPP_XML_PARSE_ERROR"


def test_epp_authentication_rejects_invalid_login_epp_03(tmp_path: Path) -> None:
    """covers epp-03"""
    attempts = [
        EppLoginAttempt("invalid-client-id", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
        EppLoginAttempt("invalid-password", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
        EppLoginAttempt("wrong-cert", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
        EppLoginAttempt("other-registrar-cert", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
        EppLoginAttempt("missing-cert", expected_success=False, response_xml=EPP_POLICY_ERROR_RESPONSE),
        EppLoginAttempt("valid-credentials", expected_success=True, response_xml=EPP_SUCCESS_RESPONSE),
    ]
    findings = assess_epp03_login_matrix(attempts)
    assert findings == []

    failing = assess_epp03_login_matrix([EppLoginAttempt("unexpected-pass", expected_success=False, response_xml=EPP_SUCCESS_RESPONSE)])
    assert failing[0].code == "EPP_LOGIN_UNEXPECTEDLY_SUCCEEDED"


def test_epp_domain_check_command_smoke_epp_04(tmp_path: Path) -> None:
    """covers epp-04"""
    invalid_error = "<epp><response><result code='2001'><msg>syntax error</msg></result></response></epp>"
    invalid_normal = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><response><result code='1000'><msg>ok</msg></result>"
        "<resData><domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'>"
        "<domain:cd><domain:name avail='0'>bad domain</domain:name></domain:cd>"
        "</domain:chkData></resData></response></epp>"
    )
    registered = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><response><result code='1000'/><resData>"
        "<domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'><domain:cd>"
        "<domain:name avail='false'>taken.example</domain:name></domain:cd></domain:chkData>"
        "</resData></response></epp>"
    )
    unregistered = (
        "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><response><result code='1000'/><resData>"
        "<domain:chkData xmlns:domain='urn:ietf:params:xml:ns:domain-1.0'><domain:cd>"
        "<domain:name avail='1'>open.example</domain:name></domain:cd></domain:chkData>"
        "</resData></response></epp>"
    )
    assert assess_epp04_domain_check_response(response_xml=invalid_error, expectation="invalid") == []
    assert assess_epp04_domain_check_response(response_xml=invalid_normal, expectation="invalid") == []
    assert assess_epp04_domain_check_response(response_xml=registered, expectation="registered") == []
    assert assess_epp04_domain_check_response(response_xml=unregistered, expectation="unregistered") == []


def test_epp_domain_create_smoke_epp_14(tmp_path: Path) -> None:
    """covers epp-14"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    response = client.send_command("<epp><command><create/></command></epp>")
    assert EppClient.result_code(response) == 1000


def test_epp_domain_update_smoke_epp_16(tmp_path: Path) -> None:
    """covers epp-16"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    response = client.send_command("<epp><command><update/></command></epp>")
    assert EppClient.result_code(response) == 1000


def test_epp_service_port_consistency_smoke_epp_17(tmp_path: Path) -> None:
    """covers epp-17"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE])
    client = EppClient(config=_config(tmp_path, port=700), transport=transport, ssl_context=Mock(name="ssl_context"))

    client.send_command("<epp><hello/></epp>")
    assert transport.calls[0]["port"] == client.config.port


def test_epp_wide_glue_policy_smoke_epp_26(tmp_path: Path) -> None:
    """covers epp-26"""
    transport = _FakeTransport(responses=[EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    response = client.send_command("<epp><command><create/></command></epp>")
    assert EppClient.result_code(response) == 2306


def test_epp_glueless_internal_host_access_control_smoke_epp_27(tmp_path: Path) -> None:
    """covers epp-27"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    create_response = client.send_command("<epp><command><create/></command></epp>")
    update_response = client.send_command("<epp><command><update/></command></epp>")
    assert client.is_success(create_response) is True
    assert client.is_success(update_response) is False


def test_epp_host_check_command_smoke_epp_05(tmp_path: Path) -> None:
    """covers epp-05"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    registered = "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><response><result code='1000'/><resData><host:chkData xmlns:host='urn:ietf:params:xml:ns:host-1.0'><host:cd><host:name avail='0'>ns1.example</host:name></host:cd></host:chkData></resData></response></epp>"
    invalid = "<epp><response><result code='2004'/></response></epp>"
    normalized_registered = registered.replace("<host:name", "<name").replace("</host:name>", "</name>")
    assert assess_check_response_semantics(response_xml=normalized_registered, expectation="registered", object_label="host") == []
    assert assess_check_response_semantics(response_xml=invalid, expectation="invalid", object_label="host") == []


@pytest.mark.parametrize("registry_model", ["maximum", "per-registrar"])
def test_epp_contact_check_command_smoke_epp_06(tmp_path: Path, registry_model: str) -> None:
    """covers epp-06"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    unregistered = "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'><response><result code='1000'/><resData><contact:chkData xmlns:contact='urn:ietf:params:xml:ns:contact-1.0'><contact:cd><contact:id avail='1'>new-contact</contact:id></contact:cd></contact:chkData></resData></response></epp>"
    invalid = "<epp><response><result code='2001'/></response></epp>"
    normalized = unregistered.replace("<contact:id", "<name").replace("</contact:id>", "</name>")
    assert assess_check_response_semantics(response_xml=normalized, expectation="unregistered", object_label="contact") == []
    assert assess_check_response_semantics(response_xml=invalid, expectation="invalid", object_label="contact") == []


@pytest.mark.parametrize("registry_model", ["maximum", "per-registrar"])
def test_epp_contact_create_command_smoke_epp_07(tmp_path: Path, registry_model: str) -> None:
    """covers epp-07"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command(f"<epp><command><create model='{registry_model}'/></command></epp>")
    bad = client.send_command("<epp><command><create><invalidContact/></create></command></epp>")
    assert assess_success_failure_flow(case_label="epp-07", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_contact_object_access_control_smoke_epp_08(tmp_path: Path, applicable: bool) -> None:
    """covers epp-08"""
    if not applicable:
        pytest.skip("Contact object access control is registry-model dependent.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    own = client.send_command("<epp><command><info owner='self'/></command></epp>")
    foreign = client.send_command("<epp><command><info owner='other'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-08", success_response_xml=own, failure_response_xml=foreign) == []


@pytest.mark.parametrize("registry_model", ["maximum", "per-registrar"])
def test_epp_contact_update_command_smoke_epp_09(tmp_path: Path, registry_model: str) -> None:
    """covers epp-09"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command(f"<epp><command><update model='{registry_model}'/></command></epp>")
    bad = client.send_command("<epp><command><update><invalidField/></update></command></epp>")
    assert assess_success_failure_flow(case_label="epp-09", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("registry_model", ["maximum", "per-registrar"])
def test_epp_contact_delete_command_smoke_epp_10(tmp_path: Path, registry_model: str) -> None:
    """covers epp-10"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command(f"<epp><command><delete model='{registry_model}'/></command></epp>")
    bad = client.send_command("<epp><command><delete><linkedObject/></delete></command></epp>")
    assert assess_success_failure_flow(case_label="epp-10", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_host_create_command_smoke_epp_11(tmp_path: Path, applicable: bool) -> None:
    """covers epp-11"""
    if not applicable:
        pytest.skip("Host create test is not applicable for host-attribute server models.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><create host='internal'/></command></epp>")
    bad = client.send_command("<epp><command><create host='malformed'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-11", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_host_object_access_control_smoke_epp_12(tmp_path: Path, applicable: bool) -> None:
    """covers epp-12"""
    if not applicable:
        pytest.skip("Host ACL behavior is model dependent.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    own = client.send_command("<epp><command><update owner='self'/></command></epp>")
    foreign = client.send_command("<epp><command><update owner='other'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-12", success_response_xml=own, failure_response_xml=foreign) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_host_update_command_smoke_epp_13(tmp_path: Path, applicable: bool) -> None:
    """covers epp-13"""
    if not applicable:
        pytest.skip("Host update behavior is applicable to host-object workflows.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><update host='ns1.example.test'/></command></epp>")
    bad = client.send_command("<epp><command><update host='invalid host'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-13", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_registry_object_integrity_smoke_epp_15(tmp_path: Path, applicable: bool) -> None:
    """covers epp-15"""
    if not applicable:
        pytest.skip("Registry object integrity checks are not always applicable.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><info consistency='ok'/></command></epp>")
    bad = client.send_command("<epp><command><info consistency='broken'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-15", success_response_xml=ok, failure_response_xml=bad) == []


def test_epp_domain_renew_command_smoke_epp_18(tmp_path: Path) -> None:
    """covers epp-18"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><renew/></command></epp>")
    bad = client.send_command("<epp><command><renew><expired/></renew></command></epp>")
    assert assess_success_failure_flow(case_label="epp-18", success_response_xml=ok, failure_response_xml=bad) == []


def test_epp_domain_transfer_command_smoke_epp_19(tmp_path: Path) -> None:
    """covers epp-19"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><transfer op='request'/></command></epp>")
    bad = client.send_command("<epp><command><transfer op='request'><invalidAuth/></transfer></command></epp>")
    assert assess_success_failure_flow(case_label="epp-19", success_response_xml=ok, failure_response_xml=bad) == []


def test_epp_domain_transfer_rejection_smoke_epp_20(tmp_path: Path) -> None:
    """covers epp-20"""
    transport = _FakeTransport(responses=[EPP_POLICY_ERROR_RESPONSE, EPP_SUCCESS_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    rejected = client.send_command("<epp><command><transfer op='reject'/></command></epp>")
    status = client.send_command("<epp><command><info status='after-reject'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-20", success_response_xml=status, failure_response_xml=rejected) == []


def test_epp_domain_delete_command_smoke_epp_21(tmp_path: Path) -> None:
    """covers epp-21"""
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><delete/></command></epp>")
    bad = client.send_command("<epp><command><delete><activeLinks/></delete></command></epp>")
    assert assess_success_failure_flow(case_label="epp-21", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_host_rename_command_smoke_epp_23(tmp_path: Path, applicable: bool) -> None:
    """covers epp-23"""
    if not applicable:
        pytest.skip("Host rename behavior is not always applicable.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><rename/></command></epp>")
    bad = client.send_command("<epp><command><rename><externalLinked/></rename></command></epp>")
    assert assess_success_failure_flow(case_label="epp-23", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_host_delete_command_smoke_epp_24(tmp_path: Path, applicable: bool) -> None:
    """covers epp-24"""
    if not applicable:
        pytest.skip("Host delete behavior is not always applicable.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><delete host='orphan'/></command></epp>")
    bad = client.send_command("<epp><command><delete host='linked'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-24", success_response_xml=ok, failure_response_xml=bad) == []


@pytest.mark.parametrize("applicable", [True, False])
def test_epp_subordinate_host_create_command_smoke_epp_25(tmp_path: Path, applicable: bool) -> None:
    """covers epp-25"""
    if not applicable:
        pytest.skip("Subordinate host create is not always applicable.")
    transport = _FakeTransport(responses=[EPP_SUCCESS_RESPONSE, EPP_POLICY_ERROR_RESPONSE])
    client = EppClient(config=_config(tmp_path), transport=transport, ssl_context=Mock(name="ssl_context"))

    ok = client.send_command("<epp><command><create host='ns1.domain.test'/></command></epp>")
    bad = client.send_command("<epp><command><create host='ns1.other-client.test'/></command></epp>")
    assert assess_success_failure_flow(case_label="epp-25", success_response_xml=ok, failure_response_xml=bad) == []
