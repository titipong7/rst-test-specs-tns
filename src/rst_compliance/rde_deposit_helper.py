from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_DEPOSIT_FILENAME_PATTERN = re.compile(
    r"^(?P<tld>[a-z0-9-]+)_(?P<deposit_date>\d{4}-\d{2}-\d{2})_(?P<deposit_type>full)_S(?P<sequence>\d+)_R(?P<revision>\d+)\.ryde$"
)


@dataclass(frozen=True)
class RdeFilenameConstraints:
    """RST API v2026.4-aligned filename constraints for RDE deposit files."""

    pattern: re.Pattern[str] = DEFAULT_DEPOSIT_FILENAME_PATTERN
    required_deposit_type: str = "full"


def _duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def _extract_registrar_ids(root: ET.Element) -> list[str]:
    registrar_ids: list[str] = []
    for registrar in root.findall(".//{*}registrar"):
        value = registrar.findtext("{*}id")
        if value and value.strip():
            registrar_ids.append(value.strip())
    return registrar_ids


def _extract_nndn_names(root: ET.Element) -> list[str]:
    nndn_names: list[str] = []
    for nndn in root.findall(".//{*}nndn"):
        value = nndn.findtext("{*}aName")
        if value and value.strip():
            nndn_names.append(value.strip())
    return nndn_names


def validate_deposit_filename(
    *,
    filename: str,
    allowed_tlds: set[str] | None = None,
    constraints: RdeFilenameConstraints | None = None,
) -> dict[str, Any]:
    effective_constraints = constraints or RdeFilenameConstraints()
    match = effective_constraints.pattern.fullmatch(filename)
    if not match:
        return {
            "is_valid": False,
            "reason": "filename does not satisfy v2026.4 naming constraints",
            "parsed": None,
        }

    parsed = match.groupdict()
    tld = parsed.get("tld", "").lower()
    if allowed_tlds and tld not in {item.lower() for item in allowed_tlds}:
        return {
            "is_valid": False,
            "reason": "filename TLD is not present in configured TLDs",
            "parsed": parsed,
        }

    if parsed.get("deposit_type", effective_constraints.required_deposit_type) != effective_constraints.required_deposit_type:
        return {
            "is_valid": False,
            "reason": "deposit type must be full",
            "parsed": parsed,
        }

    return {"is_valid": True, "reason": None, "parsed": parsed}


def validate_rde_deposit_xml(
    *,
    xml_text: str,
    deposit_filename: str,
    allowed_tlds: set[str] | None = None,
    constraints: RdeFilenameConstraints | None = None,
) -> dict[str, Any]:
    filename_validation = validate_deposit_filename(
        filename=deposit_filename,
        allowed_tlds=allowed_tlds,
        constraints=constraints,
    )

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {
            "is_valid": False,
            "errors": ["RDE_XML_PARSE_ERROR"],
            "details": {"parse_error": str(exc), "filename": filename_validation},
        }

    registrar_ids = _extract_registrar_ids(root)
    nndn_names = _extract_nndn_names(root)

    duplicate_registrar_ids = _duplicates(registrar_ids)
    duplicate_nndn_names = _duplicates(nndn_names)

    errors: list[str] = []
    if not filename_validation["is_valid"]:
        errors.append("RDE_INVALID_FILENAME")
    if duplicate_registrar_ids:
        errors.append("RDE_REGISTRAR_HAS_NON_UNIQUE_ID")
    if duplicate_nndn_names:
        errors.append("RDE_NNDN_HAS_NON_UNIQUE_NAME")

    return {
        "is_valid": not errors,
        "errors": errors,
        "details": {
            "filename": filename_validation,
            "registrar_ids": {
                "total": len(registrar_ids),
                "duplicates": duplicate_registrar_ids,
            },
            "nndn_names": {
                "total": len(nndn_names),
                "duplicates": duplicate_nndn_names,
            },
        },
    }


def generate_icann_input_manifest(
    *,
    deposit_filename: str,
    signature_filename: str,
    public_key_filename: str,
) -> dict[str, Any]:
    return {
        "inputTemplateVersion": "v2026.4",
        "service": "RDE",
        "inputParameters": {
            "rde.depositFile": deposit_filename,
            "rde.signatureFile": signature_filename,
            "rde.publicKey": public_key_filename,
        },
    }


def write_manifest_file(*, output_file: Path, manifest: dict[str, Any]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate RDE deposits and generate ICANN input manifest")
    parser.add_argument("--xml-file", required=True, type=Path, help="Path to decrypted XML deposit")
    parser.add_argument("--deposit-filename", required=True, help="Deposit filename submitted to RST")
    parser.add_argument("--signature-filename", required=True, help="Signature filename submitted to RST")
    parser.add_argument("--public-key-filename", required=True, help="Public key filename submitted to RST")
    parser.add_argument("--tld", action="append", default=[], help="Allowed TLD(s) for filename validation")
    parser.add_argument("--manifest-output", type=Path, help="Optional path to write generated manifest JSON")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    xml_text = args.xml_file.read_text(encoding="utf-8")
    validation_result = validate_rde_deposit_xml(
        xml_text=xml_text,
        deposit_filename=args.deposit_filename,
        allowed_tlds=set(args.tld) if args.tld else None,
    )

    manifest = generate_icann_input_manifest(
        deposit_filename=args.deposit_filename,
        signature_filename=args.signature_filename,
        public_key_filename=args.public_key_filename,
    )

    if args.manifest_output:
        write_manifest_file(output_file=args.manifest_output, manifest=manifest)

    print(json.dumps({"validation": validation_result, "manifest": manifest}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
