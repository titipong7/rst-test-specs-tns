"""Tests for the RST Input Parameter Generator (input_generator.py).

Covers RST test case: rst-02 (input parameter generation) for
StandardPreDelegationTest and RSPEvaluation.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from rst_compliance.input_generator import (
    EppExtensionSpec,
    IpAcl,
    RdapBaseUrls,
    RspEvaluationInput,
    StandardPreDelegationTestInput,
)


# ---------------------------------------------------------------------------
# IpAcl
# ---------------------------------------------------------------------------


def test_ip_acl_accepts_valid_ipv4() -> None:
    acl = IpAcl(cidr="192.0.2.0/24", family="ipv4")
    assert acl.to_dict() == {"cidr": "192.0.2.0/24", "family": "ipv4"}


def test_ip_acl_rejects_invalid_family() -> None:
    with pytest.raises(ValidationError, match="family"):
        IpAcl(cidr="192.0.2.0/24", family="x400")


# ---------------------------------------------------------------------------
# RdapBaseUrls
# ---------------------------------------------------------------------------


def test_rdap_base_urls_requires_https() -> None:
    with pytest.raises(ValidationError, match="HTTPS"):
        RdapBaseUrls(domain="http://rdap.example.test/")


def test_rdap_base_urls_accepts_https_url() -> None:
    urls = RdapBaseUrls(domain="https://rdap.example.test/")
    assert urls.domain == "https://rdap.example.test/"


# ---------------------------------------------------------------------------
# StandardPreDelegationTestInput
# ---------------------------------------------------------------------------


def _base_spdt() -> StandardPreDelegationTestInput:
    return StandardPreDelegationTestInput(
        tld="example",
        ns_hostnames=["ns1.example.test", "ns2.example.test"],
        rdap_base_urls=RdapBaseUrls(domain="https://rdap.example.test/"),
    )


def test_spdt_requires_at_least_one_ns() -> None:
    with pytest.raises(ValidationError, match="nameserver"):
        StandardPreDelegationTestInput(
            tld="example",
            ns_hostnames=[],
            rdap_base_urls=RdapBaseUrls(domain="https://rdap.example.test/"),
        )


def test_spdt_to_api_payload_includes_required_fields() -> None:
    payload = _base_spdt().to_api_payload()

    assert payload["inputTemplateVersion"] == "v2026.4"
    assert payload["service"] == "StandardPreDelegationTest"
    params = payload["inputParameters"]
    assert params["dns.tld"] == "example"
    assert params["dns.nameservers"] == ["ns1.example.test", "ns2.example.test"]
    assert params["rdap.baseUrls"]["domain"] == "https://rdap.example.test/"
    assert params["dnssec.required"] is True


def test_spdt_to_api_payload_includes_ip_acls_when_provided() -> None:
    spdt = StandardPreDelegationTestInput(
        tld="example",
        ns_hostnames=["ns1.example.test"],
        rdap_base_urls=RdapBaseUrls(domain="https://rdap.example.test/"),
        ip_acls=[IpAcl(cidr="203.0.113.0/24", family="ipv4")],
    )
    params = spdt.to_api_payload()["inputParameters"]

    assert params["rst.ipAcls"] == [{"cidr": "203.0.113.0/24", "family": "ipv4"}]


def test_spdt_to_api_payload_includes_epp_fields_when_provided() -> None:
    spdt = StandardPreDelegationTestInput(
        tld="example",
        ns_hostnames=["ns1.example.test"],
        rdap_base_urls=RdapBaseUrls(domain="https://rdap.example.test/"),
        epp_host="epp.example.test",
        epp_port=700,
        epp_extensions=[
            EppExtensionSpec(namespace_uri="urn:ietf:params:xml:ns:rgp-1.0", required=True)
        ],
    )
    params = spdt.to_api_payload()["inputParameters"]

    assert params["epp.host"] == "epp.example.test"
    assert params["epp.port"] == 700
    assert params["epp.extensions"][0]["namespaceUri"] == "urn:ietf:params:xml:ns:rgp-1.0"


def test_spdt_to_api_payload_excludes_optional_fields_when_absent() -> None:
    params = _base_spdt().to_api_payload()["inputParameters"]

    assert "rst.ipAcls" not in params
    assert "epp.host" not in params


# ---------------------------------------------------------------------------
# RspEvaluationInput
# ---------------------------------------------------------------------------


def _base_rsp() -> RspEvaluationInput:
    return RspEvaluationInput(
        tld="th",
        rsp_name="ThaiRegistry",
        ns_hostnames=["ns1.thairy.test"],
        rdap_base_urls=RdapBaseUrls(domain="https://rdap.th.test/"),
    )


def test_rsp_requires_at_least_one_ns() -> None:
    with pytest.raises(ValidationError, match="nameserver"):
        RspEvaluationInput(
            tld="th",
            rsp_name="ThaiRegistry",
            ns_hostnames=[],
            rdap_base_urls=RdapBaseUrls(domain="https://rdap.th.test/"),
        )


def test_rsp_idn_enabled_requires_lgr_url() -> None:
    with pytest.raises(ValidationError, match="idn_lgr_xml_url"):
        RspEvaluationInput(
            tld="th",
            rsp_name="ThaiRegistry",
            ns_hostnames=["ns1.thairy.test"],
            rdap_base_urls=RdapBaseUrls(domain="https://rdap.th.test/"),
            idn_enabled=True,
        )


def test_rsp_to_api_payload_includes_required_fields() -> None:
    payload = _base_rsp().to_api_payload()

    assert payload["inputTemplateVersion"] == "v2026.4"
    assert payload["service"] == "RSPEvaluation"
    params = payload["inputParameters"]
    assert params["dns.tld"] == "th"
    assert params["rsp.name"] == "ThaiRegistry"


def test_rsp_to_api_payload_includes_idn_fields_when_enabled() -> None:
    rsp = RspEvaluationInput(
        tld="th",
        rsp_name="ThaiRegistry",
        ns_hostnames=["ns1.thairy.test"],
        rdap_base_urls=RdapBaseUrls(domain="https://rdap.th.test/"),
        idn_enabled=True,
        idn_lgr_xml_url="https://www.iana.org/rsrc/lgr/thai-lgr.xml",
    )
    params = rsp.to_api_payload()["inputParameters"]

    assert params["idn.enabled"] is True
    assert params["idn.lgrXmlUrl"] == "https://www.iana.org/rsrc/lgr/thai-lgr.xml"


def test_rsp_to_api_payload_excludes_idn_lgr_url_when_not_enabled() -> None:
    params = _base_rsp().to_api_payload()["inputParameters"]

    assert params["idn.enabled"] is False
    assert "idn.lgrXmlUrl" not in params
