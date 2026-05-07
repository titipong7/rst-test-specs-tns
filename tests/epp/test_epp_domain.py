"""
EPP domain tests – RST 2.0 compliance.

Covers EPP domain <check>, <info>, <create>, and <delete> commands.
Test case IDs map to the RST v2.0 EPP test spec (epp-* cases in
inc/epp/cases.yaml).
"""

from __future__ import annotations

import uuid
import pytest
from lxml import etree

from tests.epp.conftest import EPPClient, EPP_NS

pytestmark = pytest.mark.epp

DOMAIN_NS = "urn:ietf:params:xml:ns:domain-1.0"


def _build_check(domain_names: list[str]) -> bytes:
    names_xml = "".join(
        f"<domain:name>{n}</domain:name>" for n in domain_names
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        f'<epp xmlns="{EPP_NS}" xmlns:domain="{DOMAIN_NS}">'
        f"  <command>"
        f"    <check>"
        f"      <domain:check>{names_xml}</domain:check>"
        f"    </check>"
        f"    <clTRID>check-{uuid.uuid4().hex[:8]}</clTRID>"
        f"  </command>"
        f"</epp>"
    ).encode()


def _build_info(domain_name: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        f'<epp xmlns="{EPP_NS}" xmlns:domain="{DOMAIN_NS}">'
        f"  <command>"
        f"    <info>"
        f'      <domain:info><domain:name hosts="all">{domain_name}</domain:name></domain:info>'
        f"    </info>"
        f"    <clTRID>info-{uuid.uuid4().hex[:8]}</clTRID>"
        f"  </command>"
        f"</epp>"
    ).encode()


class TestEPPDomainCheck:
    """RST EPP domain check tests."""

    def test_check_registered_domain_unavailable(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """
        A domain listed in epp.registeredNames MUST be reported as unavailable
        (avail='0' or avail='false').
        """
        registered = epp_config.get("registered_names", [])
        if not registered:
            pytest.skip("epp.registered_names not configured")

        domain = registered[0]
        response = epp_client.send_command(_build_check([domain]))
        code = EPPClient.result_code(response)
        assert code == 1000, f"domain:check failed with code {code}"

        ns = {"epp": EPP_NS, "domain": DOMAIN_NS}
        cd_el = response.find(".//domain:cd", ns)
        assert cd_el is not None, "<domain:cd> element not found"
        name_el = cd_el.find("domain:name", ns)
        avail = name_el.get("avail", "1") if name_el is not None else "1"
        assert avail in ("0", "false"), (
            f"Registered domain '{domain}' reported as available"
        )

    def test_check_random_domain_available(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """A randomly generated domain name MUST be reported as available."""
        registered = epp_config.get("registered_names", [])
        # Derive TLD from a configured registered name, fallback to "example"
        if registered:
            tld = registered[0].split(".")[-1]
        else:
            tld = "example"
        random_domain = f"rst-check-{uuid.uuid4().hex[:12]}.{tld}"
        response = epp_client.send_command(_build_check([random_domain]))
        code = EPPClient.result_code(response)
        assert code == 1000, f"domain:check failed with code {code}"

        ns = {"epp": EPP_NS, "domain": DOMAIN_NS}
        cd_el = response.find(".//domain:cd", ns)
        assert cd_el is not None, "<domain:cd> element not found"
        name_el = cd_el.find("domain:name", ns)
        avail = name_el.get("avail", "0") if name_el is not None else "0"
        assert avail in ("1", "true"), (
            f"Random domain '{random_domain}' reported as unavailable"
        )


class TestEPPDomainInfo:
    """RST EPP domain info tests."""

    def test_info_registered_domain(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """
        EPP <info> on a registered domain MUST return result code 1000 and a
        <domain:infData> element.
        """
        registered = epp_config.get("registered_names", [])
        if not registered:
            pytest.skip("epp.registered_names not configured")

        domain = registered[0]
        response = epp_client.send_command(_build_info(domain))
        code = EPPClient.result_code(response)
        assert code == 1000, f"domain:info failed with code {code}"

        ns = {"epp": EPP_NS, "domain": DOMAIN_NS}
        info_data = response.find(".//domain:infData", ns)
        assert info_data is not None, "<domain:infData> not found in response"

    def test_info_nonexistent_domain_returns_2303(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """
        EPP <info> on a non-existent domain MUST return result code 2303
        (Object does not exist).
        """
        registered = epp_config.get("registered_names", [])
        tld = registered[0].split(".")[-1] if registered else "example"
        nonexistent = f"nonexistent-{uuid.uuid4().hex}.{tld}"
        response = epp_client.send_command(_build_info(nonexistent))
        code = EPPClient.result_code(response)
        assert code == 2303, (
            f"Expected 2303 for non-existent domain, got {code}"
        )
