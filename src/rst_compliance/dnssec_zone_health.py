from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

import dns.dnssec
import dns.exception
import dns.name
import dns.rcode
import dns.resolver
import dns.rdatatype


SUPPORTED_ROLLOVER_ALGORITHMS = {
    8: "RSASHA256",
    13: "ECDSAP256SHA256",
}
DISALLOWED_DS_DIGEST_TYPES = {1, 12}
FAILURE_SEVERITIES = {"ERROR", "CRITICAL"}
_TAG_PATTERN = re.compile(r"\b([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)\b")


@dataclass(frozen=True)
class ZoneHealthIssue:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ZoneHealthReport:
    zone: str
    healthy: bool
    algorithm_rollover_ready: bool
    parent_ds_matches_child_dnskey: bool
    dnskey_algorithms: list[int]
    ds_algorithms: list[int]
    errors: list[ZoneHealthIssue] = field(default_factory=list)
    zonemaster_error_codes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone,
            "healthy": self.healthy,
            "algorithmRolloverReady": self.algorithm_rollover_ready,
            "parentDsMatchesChildDnskey": self.parent_ds_matches_child_dnskey,
            "dnskeyAlgorithms": self.dnskey_algorithms,
            "dsAlgorithms": self.ds_algorithms,
            "errors": [asdict(issue) for issue in self.errors],
            "zonemasterErrorCodes": self.zonemaster_error_codes,
        }


def _normalise_zone_name(zone_name: str) -> str:
    return dns.name.from_text(zone_name).to_text()


def _is_sep_dnskey(record: Any) -> bool:
    return bool(int(record.flags) & 0x0001)


def _append_issue(issues: list[ZoneHealthIssue], issue: ZoneHealthIssue) -> None:
    if issue.code not in {existing.code for existing in issues}:
        issues.append(issue)


def extract_zonemaster_error_codes(payload: Any, *, severities: Iterable[str] = FAILURE_SEVERITIES) -> list[str]:
    severity_filter = {severity.upper() for severity in severities}
    collected: list[str] = []

    def add_code(tag: str) -> None:
        code = tag if tag.startswith("ZM_") else f"ZM_{tag}"
        if code not in collected:
            collected.append(code)

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            tag = value.get("tag") or value.get("message_tag")
            level = value.get("level") or value.get("severity")
            if isinstance(tag, str) and (not severity_filter or str(level).upper() in severity_filter):
                add_code(tag)
            for nested in value.values():
                walk(nested)
            return

        if isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return collected


def extract_zonemaster_error_codes_from_text(
    text: str, *, severities: Iterable[str] = FAILURE_SEVERITIES
) -> list[str]:
    severity_filter = {severity.upper() for severity in severities}
    collected: list[str] = []

    for line in text.splitlines():
        if severity_filter and not any(severity in line.upper() for severity in severity_filter):
            continue
        for tag in _TAG_PATTERN.findall(line):
            if "_" not in tag:
                continue
            code = tag if tag.startswith("ZM_") else f"ZM_{tag}"
            if code not in collected:
                collected.append(code)
    return collected


def load_zonemaster_error_codes(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    try:
        return extract_zonemaster_error_codes(json.loads(text))
    except json.JSONDecodeError:
        return extract_zonemaster_error_codes_from_text(text)


def resolve_zone_records(
    zone_name: str, *, nameserver: str | None = None, timeout: float = 5.0
) -> tuple[list[Any], list[Any]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]

    dnskey_answer = resolver.resolve(zone_name, dns.rdatatype.DNSKEY, raise_on_no_answer=False)
    if dnskey_answer.rrset is None:
        raise dns.resolver.NoAnswer(f"No DNSKEY records returned for {zone_name}")

    ds_answer = resolver.resolve(zone_name, dns.rdatatype.DS, raise_on_no_answer=False)
    ds_records = list(ds_answer) if ds_answer.rrset is not None else []
    return list(dnskey_answer), ds_records


def validate_zone_health(
    zone_name: str,
    *,
    dnskey_records: Sequence[Any],
    ds_records: Sequence[Any],
    zonemaster_error_codes: Sequence[str] | None = None,
) -> ZoneHealthReport:
    normalised_zone_name = _normalise_zone_name(zone_name)
    issues: list[ZoneHealthIssue] = []

    dnskey_algorithms = sorted({int(record.algorithm) for record in dnskey_records})
    ds_algorithms = sorted({int(record.algorithm) for record in ds_records})
    required_algorithms = set(SUPPORTED_ROLLOVER_ALGORITHMS)
    missing_algorithms = sorted(required_algorithms.difference(dnskey_algorithms))
    algorithm_rollover_ready = not missing_algorithms
    if missing_algorithms:
        _append_issue(
            issues,
            ZoneHealthIssue(
                code="DNSSEC_INVALID_SIGNING_ALGORITHM",
                message="Zone is not ready for RSA/SHA-256 and ECDSA P-256 algorithm rollover.",
                details={
                    "missingAlgorithms": [
                        {"number": algorithm, "name": SUPPORTED_ROLLOVER_ALGORITHMS[algorithm]}
                        for algorithm in missing_algorithms
                    ]
                },
            ),
        )

    ds_related_codes: set[str] = set()
    if not ds_records:
        ds_related_codes.add("ZM_DS03_NO_DNSSEC_SUPPORT")
        _append_issue(
            issues,
            ZoneHealthIssue(
                code="ZM_DS03_NO_DNSSEC_SUPPORT",
                message="No parent DS records were returned for the zone.",
            ),
        )

    for ds_record in ds_records:
        if int(ds_record.digest_type) in DISALLOWED_DS_DIGEST_TYPES:
            _append_issue(
                issues,
                ZoneHealthIssue(
                    code="DNSSEC_INVALID_DIGEST_ALGORITHM",
                    message="Parent DS record uses a disallowed digest algorithm.",
                    details={"digestType": int(ds_record.digest_type), "keyTag": int(ds_record.key_tag)},
                ),
            )

        matching_keys = [
            dnskey_record
            for dnskey_record in dnskey_records
            if int(dnskey_record.algorithm) == int(ds_record.algorithm)
            and dns.dnssec.make_ds(normalised_zone_name, dnskey_record, int(ds_record.digest_type)) == ds_record
        ]

        if not matching_keys:
            ds_related_codes.add("ZM_DS02_NO_DNSKEY_FOR_DS")
            issues.append(
                ZoneHealthIssue(
                    code="ZM_DS02_NO_DNSKEY_FOR_DS",
                    message="Parent DS record does not match any child DNSKEY record.",
                    details={
                        "keyTag": int(ds_record.key_tag),
                        "algorithm": int(ds_record.algorithm),
                        "digestType": int(ds_record.digest_type),
                    },
                )
            )
            continue

        if not any(_is_sep_dnskey(record) for record in matching_keys):
            ds_related_codes.add("ZM_DS02_DNSKEY_NOT_SEP")
            issues.append(
                ZoneHealthIssue(
                    code="ZM_DS02_DNSKEY_NOT_SEP",
                    message="Parent DS record matches a child DNSKEY that is not flagged as SEP.",
                    details={"keyTag": int(ds_record.key_tag), "algorithm": int(ds_record.algorithm)},
                )
            )

    normalised_zonemaster_codes = list(dict.fromkeys(zonemaster_error_codes or []))
    parent_ds_matches_child_dnskey = not ds_related_codes
    healthy = not issues and not normalised_zonemaster_codes

    return ZoneHealthReport(
        zone=normalised_zone_name,
        healthy=healthy,
        algorithm_rollover_ready=algorithm_rollover_ready,
        parent_ds_matches_child_dnskey=parent_ds_matches_child_dnskey,
        dnskey_algorithms=dnskey_algorithms,
        ds_algorithms=ds_algorithms,
        errors=issues,
        zonemaster_error_codes=normalised_zonemaster_codes,
    )


def build_zone_health_report(
    zone_name: str,
    *,
    nameserver: str | None = None,
    timeout: float = 5.0,
    zonemaster_output_path: Path | None = None,
) -> ZoneHealthReport:
    zonemaster_error_codes = load_zonemaster_error_codes(zonemaster_output_path) if zonemaster_output_path else []

    try:
        dnskey_records, ds_records = resolve_zone_records(zone_name, nameserver=nameserver, timeout=timeout)
    except (dns.exception.DNSException, OSError) as exc:
        return ZoneHealthReport(
            zone=_normalise_zone_name(zone_name),
            healthy=False,
            algorithm_rollover_ready=False,
            parent_ds_matches_child_dnskey=False,
            dnskey_algorithms=[],
            ds_algorithms=[],
            errors=[
                ZoneHealthIssue(
                    code="DNSSEC_DNS_QUERY_ERROR",
                    message="DNS query failed while fetching DNSSEC records.",
                    details={"error": str(exc)},
                )
            ],
            zonemaster_error_codes=zonemaster_error_codes,
        )

    return validate_zone_health(
        zone_name,
        dnskey_records=dnskey_records,
        ds_records=ds_records,
        zonemaster_error_codes=zonemaster_error_codes,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate DNSSEC zone health for RST v2026.04 style checks."
    )
    parser.add_argument("zone", help="Zone name to validate.")
    parser.add_argument("--nameserver", help="Optional recursive resolver to use for lookups.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Lookup timeout in seconds for DNS queries.",
    )
    parser.add_argument(
        "--zonemaster-output",
        type=Path,
        help="Optional Zonemaster JSON or text output file to parse into RST-style error codes.",
    )
    args = parser.parse_args(argv)

    report = build_zone_health_report(
        args.zone,
        nameserver=args.nameserver,
        timeout=args.timeout,
        zonemaster_output_path=args.zonemaster_output,
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
