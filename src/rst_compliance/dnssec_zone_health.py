from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_ROLLOVER_ALGORITHMS = {
    8: "RSA/SHA-256",
    13: "ECDSA P-256",
}


@dataclass(frozen=True)
class DSRecord:
    key_tag: int | None
    algorithm: int | None
    digest_type: int | None
    digest: str | None


@dataclass(frozen=True)
class DNSKEYRecord:
    key_tag: int | None
    algorithm: int | None


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _parse_ds_from_text(record: str) -> DSRecord:
    parts = record.split()
    if len(parts) < 4:
        return DSRecord(key_tag=None, algorithm=None, digest_type=None, digest=None)
    key_tag, algorithm, digest_type, digest = parts[-4:]
    return DSRecord(
        key_tag=_to_int(key_tag),
        algorithm=_to_int(algorithm),
        digest_type=_to_int(digest_type),
        digest=digest,
    )


def _parse_dnskey_from_text(record: str) -> DNSKEYRecord:
    parts = record.split()
    if len(parts) < 4:
        return DNSKEYRecord(key_tag=None, algorithm=None)

    # Handles records in presentation format where the last four fields are
    # flags, protocol, algorithm and public key data.
    flags, protocol, algorithm, _public_key = parts[-4:]
    if _to_int(flags) is None or _to_int(protocol) is None:
        return DNSKEYRecord(key_tag=None, algorithm=None)

    return DNSKEYRecord(key_tag=None, algorithm=_to_int(algorithm))


def parse_ds_record(record: dict[str, Any] | str) -> DSRecord:
    if isinstance(record, str):
        return _parse_ds_from_text(record)

    return DSRecord(
        key_tag=_to_int(record.get("key_tag", record.get("keyTag"))),
        algorithm=_to_int(record.get("algorithm")),
        digest_type=_to_int(record.get("digest_type", record.get("digestType"))),
        digest=record.get("digest"),
    )


def parse_dnskey_record(record: dict[str, Any] | str) -> DNSKEYRecord:
    if isinstance(record, str):
        return _parse_dnskey_from_text(record)

    return DNSKEYRecord(
        key_tag=_to_int(record.get("key_tag", record.get("keyTag"))),
        algorithm=_to_int(record.get("algorithm")),
    )


def _extract_tag_values(value: Any) -> list[str]:
    tags: list[str] = []
    if isinstance(value, dict):
        tag = value.get("tag")
        if isinstance(tag, str):
            tags.append(tag)
        for nested in value.values():
            tags.extend(_extract_tag_values(nested))
    elif isinstance(value, list):
        for item in value:
            tags.extend(_extract_tag_values(item))
    return tags


def extract_zonemaster_tags(result: dict[str, Any]) -> list[str]:
    seen: dict[str, None] = {}
    for tag in _extract_tag_values(result):
        seen.setdefault(tag, None)
    return list(seen.keys())


def load_rst_error_codes(error_code_files: list[Path]) -> set[str]:
    error_codes: set[str] = set()
    for path in error_code_files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith((" ", "\t", "#")) and line.endswith(":"):
                error_codes.add(line[:-1])
    return error_codes


def _normalize_records_input(value: Any) -> list[dict[str, Any] | str]:
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, (str, dict))]
    if isinstance(value, dict):
        for key in ("records", "ds", "dnskey", "dnskeys"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [entry for entry in nested if isinstance(entry, (str, dict))]
    return []


def load_records(path: Path) -> list[dict[str, Any] | str]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]

    return _normalize_records_input(parsed)


def validate_zone_health(
    *,
    parent_ds_records: list[dict[str, Any] | str],
    child_dnskey_records: list[dict[str, Any] | str],
    zonemaster_result: dict[str, Any],
    rst_error_codes: set[str],
) -> dict[str, Any]:
    parsed_ds = [parse_ds_record(record) for record in parent_ds_records]
    parsed_dnskeys = [parse_dnskey_record(record) for record in child_dnskey_records]

    present_algorithms = sorted({record.algorithm for record in parsed_dnskeys if record.algorithm is not None})
    missing_algorithms = [
        name
        for algo_id, name in SUPPORTED_ROLLOVER_ALGORITHMS.items()
        if algo_id not in present_algorithms
    ]
    rollover_ready = not missing_algorithms

    parent_pairs = {
        (record.key_tag, record.algorithm)
        for record in parsed_ds
        if record.key_tag is not None and record.algorithm is not None
    }
    child_pairs = {
        (record.key_tag, record.algorithm)
        for record in parsed_dnskeys
        if record.key_tag is not None and record.algorithm is not None
    }

    unmatched_parent_ds = sorted(parent_pairs - child_pairs)
    ds_dnskey_match = not unmatched_parent_ds and bool(parent_pairs)

    zonemaster_tags = extract_zonemaster_tags(zonemaster_result)
    matched_tags = sorted(tag for tag in zonemaster_tags if tag in rst_error_codes)
    unknown_tags = sorted(tag for tag in zonemaster_tags if tag not in rst_error_codes)

    overall_status = "pass" if rollover_ready and ds_dnskey_match and not unknown_tags else "fail"

    return {
        "overall_status": overall_status,
        "algorithm_rollover_readiness": {
            "ready": rollover_ready,
            "required": SUPPORTED_ROLLOVER_ALGORITHMS,
            "present": present_algorithms,
            "missing": missing_algorithms,
        },
        "ds_dnskey_match": {
            "matched": ds_dnskey_match,
            "parent_ds_records_with_key_tag": len(parent_pairs),
            "child_dnskeys_with_key_tag": len(child_pairs),
            "unmatched_parent_ds": [
                {"key_tag": key_tag, "algorithm": algorithm}
                for key_tag, algorithm in unmatched_parent_ds
            ],
        },
        "zonemaster_tags": {
            "observed": zonemaster_tags,
            "matched_rst_codes": matched_tags,
            "unknown": unknown_tags,
        },
    }


def _default_error_code_files() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[2]
    return [
        repo_root / "inc" / "dnssec" / "errors.yaml",
        repo_root / "inc" / "dnssec-ops" / "errors.yaml",
    ]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate DNSSEC zone health for RST v2026.04 inputs")
    parser.add_argument("--parent-ds-file", required=True, type=Path, help="JSON or text file containing parent DS records")
    parser.add_argument("--child-dnskey-file", required=True, type=Path, help="JSON or text file containing child DNSKEY records")
    parser.add_argument("--zonemaster-output", required=True, type=Path, help="Zonemaster JSON output file")
    parser.add_argument(
        "--error-code-file",
        action="append",
        type=Path,
        default=None,
        help="RST error-code YAML file(s) to validate parsed tags against",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    error_code_files = args.error_code_file or _default_error_code_files()

    parent_ds_records = load_records(args.parent_ds_file)
    child_dnskey_records = load_records(args.child_dnskey_file)
    zonemaster_result = json.loads(args.zonemaster_output.read_text(encoding="utf-8"))
    rst_error_codes = load_rst_error_codes(error_code_files)

    result = validate_zone_health(
        parent_ds_records=parent_ds_records,
        child_dnskey_records=child_dnskey_records,
        zonemaster_result=zonemaster_result,
        rst_error_codes=rst_error_codes,
    )

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
