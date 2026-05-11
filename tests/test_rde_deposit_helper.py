from __future__ import annotations

import json
from pathlib import Path

from rst_compliance.rde_deposit_helper import (
    generate_icann_input_manifest,
    validate_deposit_filename,
    validate_rde_deposit_xml,
    write_manifest_file,
)


def test_validate_deposit_filename_accepts_v2026_4_pattern() -> None:
    """Covers rde-01 valid filename format and FULL deposit type."""
    result = validate_deposit_filename(
        filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is True
    assert result["parsed"]["tld"] == "example"


def test_validate_deposit_filename_rejects_non_matching_name() -> None:
    """Covers rde-01 invalid filename/deposit-type path."""
    result = validate_deposit_filename(
        filename="example_2026-04-13_incremental_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False


def test_validate_rde_deposit_xml_flags_non_unique_registrar_and_nndn() -> None:
    """Covers rde-10 registrar uniqueness and rde-12 NNDN uniqueness checks."""
    xml_text = """<?xml version='1.0' encoding='UTF-8'?>
<rdeDeposit xmlns:rdeRegistrar='urn:ietf:params:xml:ns:rdeRegistrar-1.0' xmlns:rdeNNDN='urn:ietf:params:xml:ns:rdeNNDN-1.0'>
  <rdeRegistrar:registrar>
    <rdeRegistrar:id>R-100</rdeRegistrar:id>
  </rdeRegistrar:registrar>
  <rdeRegistrar:registrar>
    <rdeRegistrar:id>R-100</rdeRegistrar:id>
  </rdeRegistrar:registrar>
  <rdeNNDN:nndn>
    <rdeNNDN:aName>blocked.example</rdeNNDN:aName>
  </rdeNNDN:nndn>
  <rdeNNDN:nndn>
    <rdeNNDN:aName>blocked.example</rdeNNDN:aName>
  </rdeNNDN:nndn>
</rdeDeposit>
"""

    result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False
    assert "RDE_REGISTRAR_HAS_NON_UNIQUE_ID" in result["errors"]
    assert "RDE_NNDN_HAS_NON_UNIQUE_NAME" in result["errors"]


def test_validate_rde_deposit_xml_rejects_malformed_xml() -> None:
    """Covers rde-04 XML parse error handling."""
    result = validate_rde_deposit_xml(
        xml_text="<rdeDeposit><invalid>",
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False
    assert result["errors"] == ["RDE_XML_PARSE_ERROR"]


def test_validate_rde_deposit_xml_flags_nndn_conflicts_with_domain_name() -> None:
    """Covers rde-12 rule that NNDN aName must not conflict with domain name."""
    xml_text = """<?xml version='1.0' encoding='UTF-8'?>
<rdeDeposit
  xmlns:rdeDomain='urn:ietf:params:xml:ns:rdeDomain-1.0'
  xmlns:rdeNNDN='urn:ietf:params:xml:ns:rdeNNDN-1.0'>
  <rdeDomain:domain>
    <rdeDomain:name>blocked.example</rdeDomain:name>
  </rdeDomain:domain>
  <rdeNNDN:nndn>
    <rdeNNDN:aName>blocked.example</rdeNNDN:aName>
    <rdeNNDN:nameState>blocked</rdeNNDN:nameState>
  </rdeNNDN:nndn>
</rdeDeposit>
"""

    result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False
    assert "RDE_NNDN_CONFLICTS_WITH_DOMAIN" in result["errors"]
    assert result["details"]["nndn_names"]["conflicts_with_domains"] == ["blocked.example"]


def test_validate_rde_deposit_xml_reports_invalid_nndn_name_state() -> None:
    """Covers rde-12 nameState domain restrictions (blocked/withheld/mirrored)."""
    xml_text = """<?xml version='1.0' encoding='UTF-8'?>
<rdeDeposit xmlns:rdeNNDN='urn:ietf:params:xml:ns:rdeNNDN-1.0' xmlns:rdeHeader='urn:ietf:params:xml:ns:rdeHeader-1.0'>
  <rdeHeader:header>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeNNDN-1.0'>1</rdeHeader:count>
  </rdeHeader:header>
  <rdeMenu>
    <objURI>urn:ietf:params:xml:ns:rdeNNDN-1.0</objURI>
  </rdeMenu>
  <rdeNNDN:nndn>
    <rdeNNDN:aName>reserved.example</rdeNNDN:aName>
    <rdeNNDN:nameState>invalid-state</rdeNNDN:nameState>
  </rdeNNDN:nndn>
</rdeDeposit>
"""

    result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is True
    assert result["errors"] == []
    assert result["details"]["nndn_name_states"]["invalid"] == ["invalid-state"]


def test_validate_rde_deposit_xml_flags_menu_header_uri_mismatch_and_count_mismatch() -> None:
    """Covers rde-05/rde-06 URI consistency and count checks."""
    xml_text = """<?xml version='1.0' encoding='UTF-8'?>
<rdeDeposit xmlns:rdeHeader='urn:ietf:params:xml:ns:rdeHeader-1.0' xmlns:rdeDomain='urn:ietf:params:xml:ns:rdeDomain-1.0'>
  <rdeHeader:header>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeDomain-1.0'>2</rdeHeader:count>
  </rdeHeader:header>
  <rdeMenu>
    <objURI>urn:ietf:params:xml:ns:rdeRegistrar-1.0</objURI>
  </rdeMenu>
  <rdeDomain:domain>
    <rdeDomain:name>example.test</rdeDomain:name>
  </rdeDomain:domain>
</rdeDeposit>
"""

    result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False
    assert "RDE_MENU_AND_HEADER_URIS_DIFFER" in result["errors"]
    assert "RDE_OBJECT_COUNT_MISMATCH" in result["errors"]


def test_validate_rde_deposit_xml_flags_missing_declared_object_types() -> None:
    """Covers rde-07/rde-08/rde-09/rde-11 object-missing checks from header URIs."""
    xml_text = """<?xml version='1.0' encoding='UTF-8'?>
<rdeDeposit xmlns:rdeHeader='urn:ietf:params:xml:ns:rdeHeader-1.0'>
  <rdeHeader:header>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeDomain-1.0'>0</rdeHeader:count>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeHost-1.0'>0</rdeHeader:count>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeContact-1.0'>0</rdeHeader:count>
    <rdeHeader:count uri='urn:ietf:params:xml:ns:rdeIDN-1.0'>0</rdeHeader:count>
  </rdeHeader:header>
</rdeDeposit>
"""

    result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False
    assert "RDE_DOMAIN_OBJECT_MISSING" in result["errors"]
    assert "RDE_HOST_OBJECT_MISSING" in result["errors"]
    assert "RDE_CONTACT_OBJECT_MISSING" in result["errors"]
    assert "RDE_IDN_OBJECT_MISSING" in result["errors"]


def test_generate_manifest_matches_icann_input_template_shape() -> None:
    """Covers rde-02/rde-03 manifest input structure used by helper workflow."""
    manifest = generate_icann_input_manifest(
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        signature_filename="example_2026-04-13_full_S1_R0.sig",
        public_key_filename="rsp-rde-signing-key.asc",
    )

    assert manifest["inputTemplateVersion"] == "v2026.4"
    assert manifest["service"] == "RDE"
    assert manifest["inputParameters"] == {
        "rde.depositFile": "example_2026-04-13_full_S1_R0.ryde",
        "rde.signatureFile": "example_2026-04-13_full_S1_R0.sig",
        "rde.publicKey": "rsp-rde-signing-key.asc",
    }


def test_write_manifest_file_writes_json(tmp_path: Path) -> None:
    output_file = tmp_path / "manifest" / "rde-manifest.json"
    manifest = generate_icann_input_manifest(
        deposit_filename="example_2026-04-13_full_S1_R0.ryde",
        signature_filename="example_2026-04-13_full_S1_R0.sig",
        public_key_filename="rsp-rde-signing-key.asc",
    )

    write_manifest_file(output_file=output_file, manifest=manifest)

    written = json.loads(output_file.read_text(encoding="utf-8"))
    assert written == manifest
