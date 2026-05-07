"""
EPP contact tests – RST 2.0 compliance.

Covers EPP contact <check> and <info> commands.
"""

from __future__ import annotations

import uuid
import pytest
from lxml import etree

from tests.epp.conftest import EPPClient, EPP_NS

pytestmark = pytest.mark.epp

CONTACT_NS = "urn:ietf:params:xml:ns:contact-1.0"


def _build_contact_check(contact_ids: list[str]) -> bytes:
    ids_xml = "".join(
        f"<contact:id>{cid}</contact:id>" for cid in contact_ids
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        f'<epp xmlns="{EPP_NS}" xmlns:contact="{CONTACT_NS}">'
        f"  <command>"
        f"    <check>"
        f"      <contact:check>{ids_xml}</contact:check>"
        f"    </check>"
        f"    <clTRID>ccheck-{uuid.uuid4().hex[:8]}</clTRID>"
        f"  </command>"
        f"</epp>"
    ).encode()


def _build_contact_info(contact_id: str) -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        f'<epp xmlns="{EPP_NS}" xmlns:contact="{CONTACT_NS}">'
        f"  <command>"
        f"    <info>"
        f"      <contact:info><contact:id>{contact_id}</contact:id></contact:info>"
        f"    </info>"
        f"    <clTRID>cinfo-{uuid.uuid4().hex[:8]}</clTRID>"
        f"  </command>"
        f"</epp>"
    ).encode()


class TestEPPContactCheck:
    """RST EPP contact check tests."""

    def test_check_registered_contact_unavailable(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """
        A contact listed in epp.registeredContacts MUST be reported as
        unavailable.
        """
        registered = epp_config.get("registered_contacts", [])
        if not registered:
            pytest.skip("epp.registered_contacts not configured")

        contact_id = registered[0]
        response = epp_client.send_command(_build_contact_check([contact_id]))
        code = EPPClient.result_code(response)
        assert code == 1000, f"contact:check failed with code {code}"

        ns = {"epp": EPP_NS, "contact": CONTACT_NS}
        cd_el = response.find(".//contact:cd", ns)
        assert cd_el is not None, "<contact:cd> element not found"
        id_el = cd_el.find("contact:id", ns)
        avail = id_el.get("avail", "1") if id_el is not None else "1"
        assert avail in ("0", "false"), (
            f"Registered contact '{contact_id}' reported as available"
        )

    def test_check_random_contact_available(self, epp_client: EPPClient) -> None:
        """A randomly generated contact ID MUST be reported as available."""
        random_id = f"rst-{uuid.uuid4().hex[:12]}"
        response = epp_client.send_command(_build_contact_check([random_id]))
        code = EPPClient.result_code(response)
        assert code == 1000, f"contact:check failed with code {code}"

        ns = {"epp": EPP_NS, "contact": CONTACT_NS}
        cd_el = response.find(".//contact:cd", ns)
        assert cd_el is not None, "<contact:cd> element not found"
        id_el = cd_el.find("contact:id", ns)
        avail = id_el.get("avail", "0") if id_el is not None else "0"
        assert avail in ("1", "true"), (
            f"Random contact '{random_id}' reported as unavailable"
        )


class TestEPPContactInfo:
    """RST EPP contact info tests."""

    def test_info_registered_contact(
        self, epp_client: EPPClient, epp_config: dict
    ) -> None:
        """EPP <info> on a registered contact MUST return 1000 and <contact:infData>."""
        registered = epp_config.get("registered_contacts", [])
        if not registered:
            pytest.skip("epp.registered_contacts not configured")

        contact_id = registered[0]
        response = epp_client.send_command(_build_contact_info(contact_id))
        code = EPPClient.result_code(response)
        assert code == 1000, f"contact:info failed with code {code}"

        ns = {"epp": EPP_NS, "contact": CONTACT_NS}
        info_data = response.find(".//contact:infData", ns)
        assert info_data is not None, "<contact:infData> not found in response"
