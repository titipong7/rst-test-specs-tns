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
ALLOWED_NNDN_NAME_STATES = {"blocked", "withheld", "mirrored"}
OBJECT_URI_SUFFIX_BY_OBJECT_TYPE = {
    "domain": ":xml:ns:rdeDomain-1.0",
    "registrar": ":xml:ns:rdeRegistrar-1.0",
    "host": ":xml:ns:rdeHost-1.0",
    "contact": ":xml:ns:rdeContact-1.0",
    "idnTable": ":xml:ns:rdeIDN-1.0",
    "nndn": ":xml:ns:rdeNNDN-1.0",
    "eppParams": ":xml:ns:rdeEppParams-1.0",
}


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


def _extract_domain_names(root: ET.Element) -> list[str]:
    domain_names: list[str] = []
    for domain in root.findall(".//{*}domain"):
        value = domain.findtext("{*}name")
        if value and value.strip():
            domain_names.append(value.strip())
    return domain_names


def _extract_nndn_name_states(root: ET.Element) -> list[str]:
    name_states: list[str] = []
    for nndn in root.findall(".//{*}nndn"):
        value = nndn.findtext("{*}nameState")
        if value and value.strip():
            name_states.append(value.strip().lower())
    return name_states


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _find_elements_by_local_name(root: ET.Element, local_name: str) -> list[ET.Element]:
    return [element for element in root.iter() if _local_name(element.tag) == local_name]


def _extract_menu_obj_uris(root: ET.Element) -> list[str]:
    values: list[str] = []
    for element in _find_elements_by_local_name(root, "objURI"):
        text = element.text or ""
        if text.strip():
            values.append(text.strip())
    return values


def _extract_header_uri_counts(root: ET.Element) -> dict[str, int]:
    uri_counts: dict[str, int] = {}
    for count_element in _find_elements_by_local_name(root, "count"):
        uri = (count_element.attrib.get("uri") or "").strip()
        if not uri:
            continue
        text = (count_element.text or "").strip()
        try:
            uri_counts[uri] = int(text)
        except ValueError:
            uri_counts[uri] = -1
    return uri_counts


def _extract_object_counts(root: ET.Element) -> dict[str, int]:
    return {
        "domain": len(_find_elements_by_local_name(root, "domain")),
        "registrar": len(_find_elements_by_local_name(root, "registrar")),
        "host": len(_find_elements_by_local_name(root, "host")),
        "contact": len(_find_elements_by_local_name(root, "contact")),
        "idnTable": len(_find_elements_by_local_name(root, "idnTable")),
        "nndn": len(_find_elements_by_local_name(root, "nndn")),
        "eppParams": len(_find_elements_by_local_name(root, "eppParams")),
    }


def _uri_matches_object_type(uri: str, object_type: str) -> bool:
    suffix = OBJECT_URI_SUFFIX_BY_OBJECT_TYPE[object_type]
    return uri.endswith(suffix)


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

    if parsed.get("deposit_type", "") != effective_constraints.required_deposit_type:
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
    domain_names = _extract_domain_names(root)
    nndn_name_states = _extract_nndn_name_states(root)

    duplicate_registrar_ids = _duplicates(registrar_ids)
    duplicate_nndn_names = _duplicates(nndn_names)
    conflicting_nndn_names = sorted(set(nndn_names) & set(domain_names))
    invalid_nndn_name_states = sorted(
        {state for state in nndn_name_states if state not in ALLOWED_NNDN_NAME_STATES}
    )
    menu_obj_uris = _extract_menu_obj_uris(root)
    header_uri_counts = _extract_header_uri_counts(root)
    object_counts = _extract_object_counts(root)
    header_uri_set = set(header_uri_counts)
    menu_uri_set = set(menu_obj_uris)

    errors: list[str] = []
    if not filename_validation["is_valid"]:
        errors.append("RDE_INVALID_FILENAME")
    if duplicate_registrar_ids:
        errors.append("RDE_REGISTRAR_HAS_NON_UNIQUE_ID")
    if duplicate_nndn_names:
        errors.append("RDE_NNDN_HAS_NON_UNIQUE_NAME")
    if conflicting_nndn_names:
        errors.append("RDE_NNDN_CONFLICTS_WITH_DOMAIN")
    if menu_uri_set and header_uri_set and menu_uri_set != header_uri_set:
        errors.append("RDE_MENU_AND_HEADER_URIS_DIFFER")

    for object_type, count in object_counts.items():
        has_uri = any(
            _uri_matches_object_type(uri, object_type) for uri in (menu_uri_set | header_uri_set)
        )
        if count > 0 and not has_uri:
            if object_type == "idnTable":
                errors.append("RDE_IDN_OBJECT_UNEXPECTED")
            else:
                errors.append("RDE_UNEXPECTED_OBJECT")

    # rde-05/06 basic URI and count checks from header/menu declarations.
    for uri, expected_count in header_uri_counts.items():
        matched_type = next(
            (object_type for object_type in OBJECT_URI_SUFFIX_BY_OBJECT_TYPE if _uri_matches_object_type(uri, object_type)),
            None,
        )
        if matched_type is None:
            errors.append("RDE_UNEXPECTED_OBJECT_URI")
            continue
        actual_count = object_counts.get(matched_type, 0)
        if expected_count < 0 or expected_count != actual_count:
            errors.append("RDE_OBJECT_COUNT_MISMATCH")
        if actual_count == 0:
            if matched_type == "domain":
                errors.append("RDE_DOMAIN_OBJECT_MISSING")
            elif matched_type == "host":
                errors.append("RDE_HOST_OBJECT_MISSING")
            elif matched_type == "contact":
                errors.append("RDE_CONTACT_OBJECT_MISSING")
            elif matched_type == "idnTable":
                errors.append("RDE_IDN_OBJECT_MISSING")

    for object_type, count in object_counts.items():
        if count == 0:
            continue
        if not any(_uri_matches_object_type(uri, object_type) for uri in menu_uri_set):
            errors.append("RDE_MISSING_OBJECT_URI")

    return {
        "is_valid": not errors,
        "errors": sorted(set(errors)),
        "details": {
            "filename": filename_validation,
            "registrar_ids": {
                "total": len(registrar_ids),
                "duplicates": duplicate_registrar_ids,
            },
            "nndn_names": {
                "total": len(nndn_names),
                "duplicates": duplicate_nndn_names,
                "conflicts_with_domains": conflicting_nndn_names,
            },
            "nndn_name_states": {
                "total": len(nndn_name_states),
                "invalid": invalid_nndn_name_states,
            },
            "menu_obj_uris": sorted(menu_uri_set),
            "header_uri_counts": header_uri_counts,
            "object_counts": object_counts,
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
