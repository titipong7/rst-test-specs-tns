from __future__ import annotations

import base64
import json
from pathlib import Path

import dns.dnssec
import dns.rrset

from rst_compliance.dnssec_zone_health import (
    build_zone_health_report,
    extract_zonemaster_error_codes,
    extract_zonemaster_error_codes_from_text,
    load_zonemaster_error_codes,
    validate_zone_health,
)


def _dnskey_text(flags: int, algorithm: int, label: str) -> str:
    return f"{flags} 3 {algorithm} {base64.b64encode(label.encode('utf-8')).decode('ascii')}"


def test_validate_zone_health_accepts_dual_algorithm_rollover_ready_zone() -> None:
    zone_name = "example."
    dnskey_rrset = dns.rrset.from_text_list(
        zone_name,
        3600,
        "IN",
        "DNSKEY",
        [
            _dnskey_text(257, 8, "rsa-ksk"),
            _dnskey_text(257, 13, "ecdsa-ksk"),
        ],
    )
    ds_records = [
        dns.dnssec.make_ds(zone_name, dnskey_rrset[0], "SHA256"),
        dns.dnssec.make_ds(zone_name, dnskey_rrset[1], "SHA256"),
    ]

    report = validate_zone_health(zone_name, dnskey_records=list(dnskey_rrset), ds_records=ds_records)

    assert report.healthy is True
    assert report.algorithm_rollover_ready is True
    assert report.parent_ds_matches_child_dnskey is True
    assert report.dnskey_algorithms == [8, 13]
    assert report.ds_algorithms == [8, 13]
    assert report.errors == []


def test_validate_zone_health_reports_missing_algorithm_and_ds_mismatch() -> None:
    zone_name = "example."
    dnskey_rrset = dns.rrset.from_text_list(
        zone_name,
        3600,
        "IN",
        "DNSKEY",
        [_dnskey_text(257, 8, "rsa-ksk")],
    )
    other_rrset = dns.rrset.from_text_list(
        zone_name,
        3600,
        "IN",
        "DNSKEY",
        [_dnskey_text(257, 8, "other-rsa-ksk")],
    )
    ds_records = [dns.dnssec.make_ds(zone_name, other_rrset[0], "SHA256")]

    report = validate_zone_health(zone_name, dnskey_records=list(dnskey_rrset), ds_records=ds_records)
    codes = [issue.code for issue in report.errors]

    assert report.healthy is False
    assert report.algorithm_rollover_ready is False
    assert report.parent_ds_matches_child_dnskey is False
    assert "DNSSEC_INVALID_SIGNING_ALGORITHM" in codes
    assert "ZM_DS02_NO_DNSKEY_FOR_DS" in codes


def test_validate_zone_health_reports_non_sep_dnskey_for_matching_ds() -> None:
    zone_name = "example."
    dnskey_rrset = dns.rrset.from_text_list(
        zone_name,
        3600,
        "IN",
        "DNSKEY",
        [
            _dnskey_text(256, 8, "rsa-zsk"),
            _dnskey_text(257, 13, "ecdsa-ksk"),
        ],
    )
    ds_records = [dns.dnssec.make_ds(zone_name, dnskey_rrset[0], "SHA256")]

    report = validate_zone_health(zone_name, dnskey_records=list(dnskey_rrset), ds_records=ds_records)
    codes = [issue.code for issue in report.errors]

    assert report.parent_ds_matches_child_dnskey is False
    assert "ZM_DS02_DNSKEY_NOT_SEP" in codes


def test_extract_zonemaster_error_codes_from_json_and_text() -> None:
    payload = {
        "results": [
            {"level": "INFO", "tag": "IGNORED_TAG"},
            {"level": "ERROR", "tag": "DS02_NO_DNSKEY_FOR_DS"},
            {"severity": "CRITICAL", "message_tag": "DS13_ALGO_NOT_SIGNED_DNSKEY"},
        ]
    }

    assert extract_zonemaster_error_codes(payload) == [
        "ZM_DS02_NO_DNSKEY_FOR_DS",
        "ZM_DS13_ALGO_NOT_SIGNED_DNSKEY",
    ]
    assert extract_zonemaster_error_codes_from_text(
        "ERROR DS02_NO_DNSKEY_FOR_DS parent and child differ\nNOTICE NO_MATCH"
    ) == ["ZM_DS02_NO_DNSKEY_FOR_DS"]


def test_load_zonemaster_error_codes_from_file_and_build_report(tmp_path: Path, monkeypatch) -> None:
    zone_name = "example."
    output_file = tmp_path / "zonemaster.json"
    output_file.write_text(
        json.dumps({"results": [{"level": "ERROR", "tag": "DS02_NO_DNSKEY_FOR_DS"}]}),
        encoding="utf-8",
    )

    dnskey_rrset = dns.rrset.from_text_list(
        zone_name,
        3600,
        "IN",
        "DNSKEY",
        [
            _dnskey_text(257, 8, "rsa-ksk"),
            _dnskey_text(257, 13, "ecdsa-ksk"),
        ],
    )
    ds_records = [
        dns.dnssec.make_ds(zone_name, dnskey_rrset[0], "SHA256"),
        dns.dnssec.make_ds(zone_name, dnskey_rrset[1], "SHA256"),
    ]

    monkeypatch.setattr(
        "rst_compliance.dnssec_zone_health.resolve_zone_records",
        lambda zone_name, nameserver=None, timeout=5.0: (list(dnskey_rrset), ds_records),
    )

    assert load_zonemaster_error_codes(output_file) == ["ZM_DS02_NO_DNSKEY_FOR_DS"]

    report = build_zone_health_report(zone_name, zonemaster_output_path=output_file)
    assert report.healthy is False
    assert report.zonemaster_error_codes == ["ZM_DS02_NO_DNSKEY_FOR_DS"]
