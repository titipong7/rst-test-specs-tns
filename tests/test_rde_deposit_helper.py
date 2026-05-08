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
    result = validate_deposit_filename(
        filename="example_2026-04-13_full_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is True
    assert result["parsed"]["tld"] == "example"


def test_validate_deposit_filename_rejects_non_matching_name() -> None:
    result = validate_deposit_filename(
        filename="example_2026-04-13_incremental_S1_R0.ryde",
        allowed_tlds={"example"},
    )

    assert result["is_valid"] is False


def test_validate_rde_deposit_xml_flags_non_unique_registrar_and_nndn() -> None:
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


def test_generate_manifest_matches_icann_input_template_shape() -> None:
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
