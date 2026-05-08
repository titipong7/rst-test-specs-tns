from __future__ import annotations

from pathlib import Path

from rst_compliance.dnssec_zone_health import load_rst_error_codes, validate_zone_health


def test_validate_zone_health_passes_with_supported_algorithms_and_matching_ds() -> None:
    parent_ds_records = [
        {"keyTag": 12345, "algorithm": 8, "digestType": 2, "digest": "AAAA"},
        {"keyTag": 23456, "algorithm": 13, "digestType": 2, "digest": "BBBB"},
    ]
    child_dnskey_records = [
        {"keyTag": 12345, "algorithm": 8},
        {"keyTag": 23456, "algorithm": 13},
    ]
    zonemaster_result = {"results": [{"tag": "DNSSEC_INVALID_SIGNING_ALGORITHM"}]}

    result = validate_zone_health(
        parent_ds_records=parent_ds_records,
        child_dnskey_records=child_dnskey_records,
        zonemaster_result=zonemaster_result,
        rst_error_codes={"DNSSEC_INVALID_SIGNING_ALGORITHM"},
    )

    assert result["overall_status"] == "pass"
    assert result["algorithm_rollover_readiness"]["ready"] is True
    assert result["ds_dnskey_match"]["matched"] is True
    assert result["zonemaster_tags"]["unknown"] == []


def test_validate_zone_health_fails_on_missing_algorithm_unmatched_ds_and_unknown_tag() -> None:
    parent_ds_records = [{"keyTag": 99999, "algorithm": 8, "digestType": 2, "digest": "CCCC"}]
    child_dnskey_records = [{"keyTag": 23456, "algorithm": 8}]
    zonemaster_result = {
        "results": [
            {"tag": "DNSSEC_INVALID_SIGNING_ALGORITHM"},
            {"sub": {"tag": "UNMAPPED_TAG"}},
        ]
    }

    result = validate_zone_health(
        parent_ds_records=parent_ds_records,
        child_dnskey_records=child_dnskey_records,
        zonemaster_result=zonemaster_result,
        rst_error_codes={"DNSSEC_INVALID_SIGNING_ALGORITHM"},
    )

    assert result["overall_status"] == "fail"
    assert result["algorithm_rollover_readiness"]["ready"] is False
    assert "ECDSA P-256" in result["algorithm_rollover_readiness"]["missing"]
    assert result["ds_dnskey_match"]["matched"] is False
    assert result["ds_dnskey_match"]["unmatched_parent_ds"] == [{"key_tag": 99999, "algorithm": 8}]
    assert result["zonemaster_tags"]["unknown"] == ["UNMAPPED_TAG"]


def test_load_rst_error_codes_reads_top_level_yaml_keys(tmp_path: Path) -> None:
    errors_file = tmp_path / "errors.yaml"
    errors_file.write_text(
        """DNSSEC_INVALID_SIGNING_ALGORITHM:\n"
        "  Severity: ERROR\n"
        "DNSSEC_DNS_QUERY_ERROR:\n"
        "  Severity: ERROR\n"
        """,
        encoding="utf-8",
    )

    codes = load_rst_error_codes([errors_file])

    assert codes == {"DNSSEC_INVALID_SIGNING_ALGORITHM", "DNSSEC_DNS_QUERY_ERROR"}
