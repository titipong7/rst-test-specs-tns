"""Input Parameter Generator for ICANN RST v2.0.

Generates well-formed JSON payloads for the two primary test plans:
  - StandardPreDelegationTest
  - RSPEvaluation

The generated payloads match the inputParameters shape expected by the
RST API (v2026.04 inputTemplateVersion).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, field_validator, model_validator


class IpAcl(BaseModel):
    """An IPv4 or IPv6 CIDR block for RST IP ACL parameters."""

    cidr: str
    family: str = "ipv4"

    @field_validator("family")
    @classmethod
    def _validate_family(cls, value: str) -> str:
        if value not in {"ipv4", "ipv6"}:
            raise ValueError(f"IP family must be 'ipv4' or 'ipv6', got {value!r}")
        return value

    def to_dict(self) -> dict[str, str]:
        return {"cidr": self.cidr, "family": self.family}


class RdapBaseUrls(BaseModel):
    """RDAP base URL set for a single TLD."""

    domain: str
    nameserver: str | None = None
    entity: str | None = None

    @field_validator("domain")
    @classmethod
    def _must_start_with_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError(f"RDAP base URL must use HTTPS, got {value!r}")
        return value


class EppExtensionSpec(BaseModel):
    """Describes an EPP extension declared in the RST input manifest."""

    namespace_uri: str
    version: str = "1.0"
    required: bool = True


class StandardPreDelegationTestInput(BaseModel):
    """Input parameters for a StandardPreDelegationTest.

    Maps to the RST API inputParameters block for the
    StandardPreDelegationTest service type.
    """

    tld: str
    ns_hostnames: list[str]
    rdap_base_urls: RdapBaseUrls
    ip_acls: list[IpAcl] = []
    epp_host: str | None = None
    epp_port: int = 700
    epp_extensions: list[EppExtensionSpec] = []
    dnssec_required: bool = True
    test_plan: str = "StandardPreDelegationTest"
    input_template_version: str = "v2026.4"

    @model_validator(mode="after")
    def _ns_not_empty(self) -> "StandardPreDelegationTestInput":
        if not self.ns_hostnames:
            raise ValueError("At least one nameserver hostname is required")
        return self

    def to_api_payload(self) -> dict[str, Any]:
        """Return the RST API-compatible inputParameters payload."""
        params: dict[str, Any] = {
            "dns.tld": self.tld,
            "dns.nameservers": self.ns_hostnames,
            "rdap.baseUrls": {
                "domain": self.rdap_base_urls.domain,
            },
            "dnssec.required": self.dnssec_required,
        }

        if self.rdap_base_urls.nameserver:
            params["rdap.baseUrls"]["nameserver"] = self.rdap_base_urls.nameserver
        if self.rdap_base_urls.entity:
            params["rdap.baseUrls"]["entity"] = self.rdap_base_urls.entity

        if self.ip_acls:
            params["rst.ipAcls"] = [acl.to_dict() for acl in self.ip_acls]

        if self.epp_host:
            params["epp.host"] = self.epp_host
            params["epp.port"] = self.epp_port

        if self.epp_extensions:
            params["epp.extensions"] = [
                {
                    "namespaceUri": ext.namespace_uri,
                    "version": ext.version,
                    "required": ext.required,
                }
                for ext in self.epp_extensions
            ]

        return {
            "inputTemplateVersion": self.input_template_version,
            "service": self.test_plan,
            "inputParameters": params,
        }


class RspEvaluationInput(BaseModel):
    """Input parameters for an RSPEvaluation.

    Maps to the RST API inputParameters block for the RSPEvaluation
    service type, used when evaluating a Registry Service Provider.
    """

    tld: str
    rsp_name: str
    ns_hostnames: list[str]
    rdap_base_urls: RdapBaseUrls
    ip_acls: list[IpAcl] = []
    epp_host: str | None = None
    epp_port: int = 700
    epp_extensions: list[EppExtensionSpec] = []
    dnssec_required: bool = True
    idn_enabled: bool = False
    idn_lgr_xml_url: str | None = None
    test_plan: str = "RSPEvaluation"
    input_template_version: str = "v2026.4"

    @model_validator(mode="after")
    def _validate_idn_fields(self) -> "RspEvaluationInput":
        if not self.ns_hostnames:
            raise ValueError("At least one nameserver hostname is required")
        if self.idn_enabled and not self.idn_lgr_xml_url:
            raise ValueError("idn_lgr_xml_url is required when idn_enabled is True")
        return self

    def to_api_payload(self) -> dict[str, Any]:
        """Return the RST API-compatible inputParameters payload."""
        params: dict[str, Any] = {
            "dns.tld": self.tld,
            "rsp.name": self.rsp_name,
            "dns.nameservers": self.ns_hostnames,
            "rdap.baseUrls": {
                "domain": self.rdap_base_urls.domain,
            },
            "dnssec.required": self.dnssec_required,
            "idn.enabled": self.idn_enabled,
        }

        if self.rdap_base_urls.nameserver:
            params["rdap.baseUrls"]["nameserver"] = self.rdap_base_urls.nameserver
        if self.rdap_base_urls.entity:
            params["rdap.baseUrls"]["entity"] = self.rdap_base_urls.entity

        if self.ip_acls:
            params["rst.ipAcls"] = [acl.to_dict() for acl in self.ip_acls]

        if self.epp_host:
            params["epp.host"] = self.epp_host
            params["epp.port"] = self.epp_port

        if self.epp_extensions:
            params["epp.extensions"] = [
                {
                    "namespaceUri": ext.namespace_uri,
                    "version": ext.version,
                    "required": ext.required,
                }
                for ext in self.epp_extensions
            ]

        if self.idn_enabled and self.idn_lgr_xml_url:
            params["idn.lgrXmlUrl"] = self.idn_lgr_xml_url

        return {
            "inputTemplateVersion": self.input_template_version,
            "service": self.test_plan,
            "inputParameters": params,
        }
