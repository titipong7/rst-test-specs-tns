from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_ALGORITHMS = {8, 13}  # RSASHA256, ECDSAP256SHA256
DEFAULT_RST_ERROR_FILES = (
    Path("inc/dnssec/errors.yaml"),
    Path("inc/dnssec-ops/errors.yaml"),
)


@dataclass(frozen=True)
class DNSKEYRecord:
    owner: str
    flags: int
    protocol: int
    algorithm: int
    public_key_b64: str


@dataclass(frozen=True)
class DSRecord:
    owner: str
    key_tag: int
    algorithm: int
    digest_type: int
    digest_hex: str


def _normalize_zone_name(name: str) -> str:
    return name.rstrip(".").lower() + "."


def _name_to_wire(name: str) -> bytes:
    fqdn = _normalize_zone_name(name)
    labels = fqdn.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        encoded = label.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _dnskey_rdata(key: DNSKEYRecord) -> bytes:
    key_bytes = base64.b64decode(key.public_key_b64.encode("ascii"), validate=True)
    return key.flags.to_bytes(2, "big") + bytes([key.protocol, key.algorithm]) + key_bytes


def dnskey_key_tag(key: DNSKEYRecord) -> int:
    rdata = _dnskey_rdata(key)
    acc = 0
    for index, value in enumerate(rdata):
        acc += value << 8 if index % 2 == 0 else value
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def _digest_bytes(data: bytes, digest_type: int) -> bytes | None:
    if digest_type == 2:
        return hashlib.sha256(data).digest()
    if digest_type == 4:
        return hashlib.sha384(data).digest()
    return None


def compute_ds_digest_hex(*, zone_name: str, dnskey: DNSKEYRecord, digest_type: int) -> str | None:
    owner_wire = _name_to_wire(zone_name)
    wire = owner_wire + _dnskey_rdata(dnskey)
    digest = _digest_bytes(wire, digest_type)
    if digest is None:
        return None
    return digest.hex().upper()


def parse_dnskey_answers(dig_output: str) -> list[DNSKEYRecord]:
    records: list[DNSKEYRecord] = []
    for line in dig_output.splitlines():
        line = line.strip()
        if not line or " DNSKEY " not in line:
            continue
        parts = line.split()
        try:
            idx = parts.index("DNSKEY")
            owner = parts[0]
            flags = int(parts[idx + 1])
            protocol = int(parts[idx + 2])
            algorithm = int(parts[idx + 3])
            public_key_b64 = "".join(parts[idx + 4 :])
        except (ValueError, IndexError):
            continue
        records.append(
            DNSKEYRecord(
                owner=owner,
                flags=flags,
                protocol=protocol,
                algorithm=algorithm,
                public_key_b64=public_key_b64,
            )
        )
    return records


def parse_ds_answers(dig_output: str) -> list[DSRecord]:
    records: list[DSRecord] = []
    for line in dig_output.splitlines():
        line = line.strip()
        if not line or " DS " not in line:
            continue
        parts = line.split()
        try:
            idx = parts.index("DS")
            owner = parts[0]
            key_tag = int(parts[idx + 1])
            algorithm = int(parts[idx + 2])
            digest_type = int(parts[idx + 3])
            digest_hex = "".join(parts[idx + 4 :]).upper()
        except (ValueError, IndexError):
            continue
        records.append(
            DSRecord(
                owner=owner,
                key_tag=key_tag,
                algorithm=algorithm,
                digest_type=digest_type,
                digest_hex=digest_hex,
            )
        )
    return records


def check_algorithm_rollover_readiness(dnskeys: list[DNSKEYRecord]) -> dict[str, Any]:
    algorithms = {record.algorithm for record in dnskeys}
    missing = sorted(REQUIRED_ALGORITHMS - algorithms)
    return {
        "supportedAlgorithms": sorted(algorithms),
        "requiredAlgorithms": sorted(REQUIRED_ALGORITHMS),
        "ready": len(missing) == 0,
        "missingAlgorithms": missing,
    }


def check_ds_dnskey_match(*, zone_name: str, ds_records: list[DSRecord], dnskeys: list[DNSKEYRecord]) -> dict[str, Any]:
    mismatches: list[dict[str, Any]] = []
    for ds in ds_records:
        matched = False
        for key in dnskeys:
            if key.algorithm != ds.algorithm:
                continue
            if dnskey_key_tag(key) != ds.key_tag:
                continue
            expected_digest = compute_ds_digest_hex(zone_name=zone_name, dnskey=key, digest_type=ds.digest_type)
            if expected_digest is None:
                continue
            if expected_digest == ds.digest_hex:
                matched = True
                break
        if not matched:
            mismatches.append(
                {
                    "owner": ds.owner,
                    "keyTag": ds.key_tag,
                    "algorithm": ds.algorithm,
                    "digestType": ds.digest_type,
                    "digest": ds.digest_hex,
                }
            )

    return {
        "match": len(mismatches) == 0,
        "mismatchedDsRecords": mismatches,
    }


def extract_error_tags_from_zonemaster_output(payload: Any) -> list[str]:
    tags: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            tag = node.get("tag")
            if isinstance(tag, str):
                tags.append(tag)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return tags


def load_rst_error_codes(files: list[Path] | None = None) -> set[str]:
    target_files = files or [path for path in DEFAULT_RST_ERROR_FILES if path.exists()]
    codes: set[str] = set()
    for path in target_files:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith(":") and " " not in stripped:
                codes.add(stripped[:-1])
    return codes


def map_tags_to_rst_error_codes(tags: list[str], rst_error_codes: set[str]) -> dict[str, list[str]]:
    matched: list[str] = []
    unmatched: list[str] = []

    for tag in tags:
        if tag in rst_error_codes:
            matched.append(tag)
            continue

        prefixed = f"ZM_{tag}"
        if prefixed in rst_error_codes:
            matched.append(prefixed)
            continue

        unmatched.append(tag)

    return {"matched": sorted(set(matched)), "unmatched": sorted(set(unmatched))}


def query_dns_records(*, zone: str, record_type: str, resolver: str | None = None) -> str:
    command = ["dig", "+noall", "+answer"]
    if resolver:
        command.append(f"@{resolver}")
    command.extend([zone, record_type])

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"dig command failed for {record_type}")
    return result.stdout


def validate_zone_health(*, zone: str, resolver: str | None = None, zonemaster_output: Any | None = None) -> dict[str, Any]:
    dnskey_output = query_dns_records(zone=zone, record_type="DNSKEY", resolver=resolver)
    ds_output = query_dns_records(zone=zone, record_type="DS", resolver=resolver)

    dnskeys = parse_dnskey_answers(dnskey_output)
    ds_records = parse_ds_answers(ds_output)

    rollover = check_algorithm_rollover_readiness(dnskeys)
    ds_match = check_ds_dnskey_match(zone_name=zone, ds_records=ds_records, dnskeys=dnskeys)

    rst_codes = load_rst_error_codes()
    derived_tags: list[str] = []
    if not rollover["ready"]:
        derived_tags.append("DNSSEC_INVALID_SIGNING_ALGORITHM")
    if not ds_match["match"]:
        derived_tags.append("DNSSEC_OPS_ALGORITHM_ROLLOVER_CHAIN_OF_TRUST_BROKEN")

    zonemaster_tags: list[str] = []
    if zonemaster_output is not None:
        zonemaster_tags = extract_error_tags_from_zonemaster_output(zonemaster_output)

    tag_map = map_tags_to_rst_error_codes(derived_tags + zonemaster_tags, rst_codes)

    return {
        "zone": zone,
        "algorithmRolloverReadiness": rollover,
        "dsDnskeyValidation": ds_match,
        "capturedErrorTags": sorted(set(derived_tags + zonemaster_tags)),
        "rstErrorCodeMapping": tag_map,
        "healthy": rollover["ready"] and ds_match["match"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate DNSSEC zone health for RST v2026.04 criteria")
    parser.add_argument("zone", help="Zone name to validate")
    parser.add_argument("--resolver", help="Resolver IP/name to use with dig")
    parser.add_argument("--zonemaster-output", help="Path to Zonemaster JSON output file")
    args = parser.parse_args()

    zonemaster_payload = None
    if args.zonemaster_output:
        zonemaster_payload = json.loads(Path(args.zonemaster_output).read_text(encoding="utf-8"))

    report = validate_zone_health(zone=args.zone, resolver=args.resolver, zonemaster_output=zonemaster_payload)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
