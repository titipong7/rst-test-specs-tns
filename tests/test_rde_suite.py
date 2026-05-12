"""Tests for the StandardRDE test suite (rde-01 … rde-14)."""
from __future__ import annotations

from typing import Any

import pytest

from rst_compliance.rde_suite import (
    Rde01FilenameChecker,
    Rde02SignatureChecker,
    Rde03DecryptionChecker,
    Rde04XmlCsvChecker,
    Rde05ObjectTypesChecker,
    Rde07DomainChecker,
    Rde08HostChecker,
    Rde09ContactChecker,
    Rde10RegistrarChecker,
    Rde11IdnChecker,
    Rde12NndnChecker,
    Rde13EppParamsChecker,
    Rde14PolicyChecker,
    RdeDepositParser,
    RdeSuiteConfig,
    StandardRdeTestSuite,
)


# ---------------------------------------------------------------------------
# Minimal valid deposit XML for testing
# ---------------------------------------------------------------------------

VALID_DEPOSIT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
  <watermark>2026-05-01T00:00:00Z</watermark>
  <rdeMenu>
    <objURI>urn:ietf:params:xml:ns:rdeDomain-1.0</objURI>
    <objURI>urn:ietf:params:xml:ns:rdeRegistrar-1.0</objURI>
  </rdeMenu>
  <rdeHeader>
    <count uri="urn:ietf:params:xml:ns:rdeDomain-1.0">1</count>
    <count uri="urn:ietf:params:xml:ns:rdeRegistrar-1.0">1</count>
  </rdeHeader>
  <registrar>
    <id>REG-1</id>
    <name>Test Registrar</name>
    <gurid>9999</gurid>
  </registrar>
  <domain>
    <name>test.example</name>
    <roid>DOM-1_EXAMPLE</roid>
    <status s="ok"/>
    <clID>REG-1</clID>
    <crDate>2025-01-01T00:00:00Z</crDate>
    <exDate>2027-01-01T00:00:00Z</exDate>
  </domain>
  <eppParams>
    <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
    <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
    <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
  </eppParams>
  <policy/>
</deposit>
"""

DEPOSIT_WITH_CONTACTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
  <watermark>2026-05-01T00:00:00Z</watermark>
  <registrar><id>REG-1</id><name>Test Registrar</name><gurid>9999</gurid></registrar>
  <domain>
    <name>test.example</name><roid>DOM-1_EXAMPLE</roid><status s="ok"/>
    <registrant>CON-1</registrant><clID>REG-1</clID>
    <crDate>2025-01-01T00:00:00Z</crDate><exDate>2027-01-01T00:00:00Z</exDate>
  </domain>
  <contact>
    <id>CON-1</id><roid>CON-1_EXAMPLE</roid><clID>REG-1</clID>
    <postalInfo type="int"><name>John</name><city>NYC</city><cc>US</cc></postalInfo>
    <email>john@example.com</email>
  </contact>
  <eppParams>
    <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
    <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
    <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
  </eppParams>
  <policy/>
</deposit>
"""

DEPOSIT_WITH_HOSTS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
  <watermark>2026-05-01T00:00:00Z</watermark>
  <registrar><id>REG-1</id><name>Test Registrar</name><gurid>9999</gurid></registrar>
  <domain>
    <name>test.example</name><roid>DOM-1_EXAMPLE</roid><status s="ok"/>
    <clID>REG-1</clID><crDate>2025-01-01T00:00:00Z</crDate><exDate>2027-01-01T00:00:00Z</exDate>
  </domain>
  <host>
    <name>ns1.test.example</name><roid>HOST-1_EXAMPLE</roid><status s="ok"/>
    <clID>REG-1</clID><addr>93.184.216.34</addr>
  </host>
  <eppParams>
    <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
    <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
    <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
  </eppParams>
</deposit>
"""


@pytest.fixture
def base_config() -> RdeSuiteConfig:
    return RdeSuiteConfig(
        deposit_filename="example_2026-05-01_full_S1_R0.ryde",
        deposit_xml=DEPOSIT_WITH_HOSTS_XML,
        signature_valid=True,
        decryption_ok=True,
        registry_data_model="minimum",
        host_model="objects",
        tlds=["example"],
    )


# ===================================================================
# rde-01: Filename validation
# ===================================================================

class TestRde01Filename:
    def test_valid_filename_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde01FilenameChecker(base_config).run()
        assert result.test_id == "rde-01"
        assert result.passed

    def test_invalid_filename_fails(self) -> None:
        config = RdeSuiteConfig(deposit_filename="bad-filename.tar.gz")
        result = Rde01FilenameChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_INVALID_FILENAME" for e in result.errors)

    def test_wrong_tld_fails(self) -> None:
        config = RdeSuiteConfig(deposit_filename="other_2026-05-01_full_S1_R0.ryde", tlds=["example"])
        result = Rde01FilenameChecker(config).run()
        assert not result.passed

    def test_empty_filename_fails(self) -> None:
        config = RdeSuiteConfig(deposit_filename="")
        result = Rde01FilenameChecker(config).run()
        assert not result.passed


# ===================================================================
# rde-02: Signature validation
# ===================================================================

class TestRde02Signature:
    def test_valid_signature_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde02SignatureChecker(base_config).run()
        assert result.passed

    def test_invalid_signature_fails(self) -> None:
        config = RdeSuiteConfig(signature_valid=False)
        result = Rde02SignatureChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_INVALID_SIGNATURE" for e in result.errors)

    def test_none_signature_passes(self) -> None:
        config = RdeSuiteConfig(signature_valid=None)
        result = Rde02SignatureChecker(config).run()
        assert result.passed


# ===================================================================
# rde-03: Decryption
# ===================================================================

class TestRde03Decryption:
    def test_successful_decryption_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde03DecryptionChecker(base_config).run()
        assert result.passed

    def test_failed_decryption_fails(self) -> None:
        config = RdeSuiteConfig(decryption_ok=False)
        result = Rde03DecryptionChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_DECRYPTION_FAILED" for e in result.errors)


# ===================================================================
# rde-04: XML/CSV validation
# ===================================================================

class TestRde04XmlCsv:
    def test_valid_xml_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde04XmlCsvChecker(base_config).run()
        assert result.passed

    def test_invalid_xml_fails(self) -> None:
        config = RdeSuiteConfig(deposit_xml="<not-valid-xml")
        result = Rde04XmlCsvChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_XML_PARSE_ERROR" for e in result.errors)

    def test_no_xml_fails(self) -> None:
        config = RdeSuiteConfig(deposit_xml="")
        result = Rde04XmlCsvChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_MISSING_FILES" for e in result.errors)


# ===================================================================
# rde-05: Object types (header/menu URIs)
# ===================================================================

class TestRde05ObjectTypes:
    def test_matching_uris_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde05ObjectTypesChecker(base_config).run()
        assert result.passed

    def test_mismatched_uris_fails(self) -> None:
        xml = """<?xml version="1.0"?>
        <deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
          <rdeMenu><objURI>urn:a</objURI></rdeMenu>
          <rdeHeader><count uri="urn:b">1</count></rdeHeader>
        </deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde05ObjectTypesChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_MENU_AND_HEADER_URIS_DIFFER" for e in result.errors)


# ===================================================================
# rde-07: Domain objects
# ===================================================================

class TestRde07Domain:
    def test_valid_domains_pass(self, base_config: RdeSuiteConfig) -> None:
        result = Rde07DomainChecker(base_config).run()
        assert result.passed

    def test_no_domains_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <registrar><id>REG-1</id><name>T</name><gurid>9</gurid></registrar></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde07DomainChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_DOMAIN_OBJECT_MISSING" for e in result.errors)

    def test_duplicate_domain_name_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <registrar><id>R</id><name>T</name><gurid>1</gurid></registrar>
        <domain><name>dup.example</name><roid>A-1_E</roid><status s="ok"/><clID>R</clID><crDate>2025-01-01T00:00:00Z</crDate></domain>
        <domain><name>dup.example</name><roid>A-2_E</roid><status s="ok"/><clID>R</clID><crDate>2025-01-01T00:00:00Z</crDate></domain>
        </deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde07DomainChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_DOMAIN_HAS_NON_UNIQUE_NAME" for e in result.errors)

    def test_missing_registrant_for_maximum_model(self) -> None:
        config = RdeSuiteConfig(deposit_xml=VALID_DEPOSIT_XML, registry_data_model="maximum")
        result = Rde07DomainChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_DOMAIN_HAS_MISSING_REGISTRANT" for e in result.errors)

    def test_invalid_roid_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <registrar><id>R</id><name>T</name><gurid>1</gurid></registrar>
        <domain><name>t.example</name><roid>BAD ROID</roid><status s="ok"/><clID>R</clID><crDate>2025-01-01T00:00:00Z</crDate></domain>
        </deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde07DomainChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_DOMAIN_HAS_INVALID_ROID" for e in result.errors)


# ===================================================================
# rde-08: Host objects
# ===================================================================

class TestRde08Host:
    def test_valid_hosts_pass(self) -> None:
        config = RdeSuiteConfig(deposit_xml=DEPOSIT_WITH_HOSTS_XML, host_model="objects")
        result = Rde08HostChecker(config).run()
        assert result.passed

    def test_skipped_when_attributes(self) -> None:
        config = RdeSuiteConfig(deposit_xml=DEPOSIT_WITH_HOSTS_XML, host_model="attributes")
        result = Rde08HostChecker(config).run()
        assert result.skipped

    def test_no_hosts_fails(self) -> None:
        config = RdeSuiteConfig(deposit_xml=VALID_DEPOSIT_XML, host_model="objects")
        result = Rde08HostChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_HOST_OBJECT_MISSING" for e in result.errors)


# ===================================================================
# rde-09: Contact objects
# ===================================================================

class TestRde09Contact:
    def test_skipped_when_minimum(self, base_config: RdeSuiteConfig) -> None:
        result = Rde09ContactChecker(base_config).run()
        assert result.skipped

    def test_valid_contacts_pass(self) -> None:
        config = RdeSuiteConfig(deposit_xml=DEPOSIT_WITH_CONTACTS_XML, registry_data_model="maximum")
        result = Rde09ContactChecker(config).run()
        assert result.passed

    def test_invalid_email_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <contact><id>C1</id><roid>C-1_E</roid><clID>R</clID>
        <postalInfo type="int"><name>J</name><city>X</city><cc>US</cc></postalInfo>
        <email>not-an-email</email></contact></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml, registry_data_model="maximum")
        result = Rde09ContactChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_CONTACT_HAS_INVALID_EMAIL" for e in result.errors)


# ===================================================================
# rde-10: Registrar objects
# ===================================================================

class TestRde10Registrar:
    def test_valid_registrar_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde10RegistrarChecker(base_config).run()
        assert result.passed

    def test_no_registrars_fails(self) -> None:
        xml = '<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0"></deposit>'
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde10RegistrarChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_REGISTRAR_OBJECT_MISSING" for e in result.errors)

    def test_missing_gurid_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <registrar><id>R</id><name>T</name></registrar></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde10RegistrarChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_REGISTRAR_HAS_MISSING_GURID" for e in result.errors)

    def test_duplicate_id_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <registrar><id>R</id><name>T1</name><gurid>1</gurid></registrar>
        <registrar><id>R</id><name>T2</name><gurid>2</gurid></registrar></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde10RegistrarChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_REGISTRAR_HAS_NON_UNIQUE_ID" for e in result.errors)


# ===================================================================
# rde-11: IDN table objects
# ===================================================================

class TestRde11Idn:
    def test_no_idn_tables_skips(self, base_config: RdeSuiteConfig) -> None:
        result = Rde11IdnChecker(base_config).run()
        assert result.skipped


# ===================================================================
# rde-12: NNDN objects
# ===================================================================

class TestRde12Nndn:
    def test_no_nndn_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde12NndnChecker(base_config).run()
        assert result.passed

    def test_nndn_conflicts_with_domain_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <domain><name>conflict.example</name><roid>D-1_E</roid><status s="ok"/><clID>R</clID><crDate>2025-01-01T00:00:00Z</crDate></domain>
        <nndn><aName>conflict.example</aName><nameState>blocked</nameState></nndn></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde12NndnChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_NNDN_CONFLICTS_WITH_DOMAIN" for e in result.errors)

    def test_duplicate_nndn_name_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <nndn><aName>dup.example</aName><nameState>blocked</nameState></nndn>
        <nndn><aName>dup.example</aName><nameState>withheld</nameState></nndn></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde12NndnChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_NNDN_HAS_NON_UNIQUE_NAME" for e in result.errors)


# ===================================================================
# rde-13: EPP parameters
# ===================================================================

class TestRde13EppParams:
    def test_valid_epp_params_passes(self, base_config: RdeSuiteConfig) -> None:
        result = Rde13EppParamsChecker(base_config).run()
        assert result.passed

    def test_missing_epp_params_fails(self) -> None:
        xml = '<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0"></deposit>'
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde13EppParamsChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_MISSING_EPP_PARAMS_OBJECT" for e in result.errors)

    def test_missing_required_exturi_fails(self) -> None:
        xml = """<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0">
        <eppParams><objURI>urn:ietf:params:xml:ns:domain-1.0</objURI></eppParams></deposit>"""
        config = RdeSuiteConfig(deposit_xml=xml)
        result = Rde13EppParamsChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_EPP_PARAMS_MISSING_EXTURI" for e in result.errors)


# ===================================================================
# rde-14: Policy object
# ===================================================================

class TestRde14Policy:
    def test_minimum_model_skips_policy_check(self, base_config: RdeSuiteConfig) -> None:
        result = Rde14PolicyChecker(base_config).run()
        assert result.passed

    def test_maximum_model_with_policy_passes(self) -> None:
        config = RdeSuiteConfig(deposit_xml=VALID_DEPOSIT_XML, registry_data_model="maximum")
        result = Rde14PolicyChecker(config).run()
        assert result.passed

    def test_maximum_model_without_policy_fails(self) -> None:
        xml = '<?xml version="1.0"?><deposit xmlns="urn:ietf:params:xml:ns:rde-1.0"></deposit>'
        config = RdeSuiteConfig(deposit_xml=xml, registry_data_model="maximum")
        result = Rde14PolicyChecker(config).run()
        assert not result.passed
        assert any(e.code == "RDE_POLICY_OBJECT_MISSING" for e in result.errors)


# ===================================================================
# Suite runner
# ===================================================================

class TestStandardRdeTestSuite:
    def test_runs_all_14_cases(self, base_config: RdeSuiteConfig) -> None:
        suite = StandardRdeTestSuite(base_config)
        results = suite.run_all()
        assert len(results) == 14
        test_ids = [r.test_id for r in results]
        for i in range(1, 15):
            assert f"rde-{i:02d}" in test_ids, f"Missing rde-{i:02d}"

    def test_all_pass_with_valid_deposit(self, base_config: RdeSuiteConfig) -> None:
        suite = StandardRdeTestSuite(base_config)
        results = suite.run_all()
        failing = [r for r in results if not r.passed and not r.skipped]
        assert not failing, f"Unexpected failures: {[(r.test_id, r.errors) for r in failing]}"
