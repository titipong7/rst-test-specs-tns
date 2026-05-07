from __future__ import annotations

from rst_compliance.dnssec_zone_health import (
    DNSKEYRecord,
    DSRecord,
    check_algorithm_rollover_readiness,
    check_ds_dnskey_match,
    compute_ds_digest_hex,
    dnskey_key_tag,
    extract_error_tags_from_zonemaster_output,
    map_tags_to_rst_error_codes,
)


def test_algorithm_rollover_readiness_requires_rsa_and_ecdsa() -> None:
    dnskeys = [
        DNSKEYRecord(owner="example.", flags=257, protocol=3, algorithm=8, public_key_b64="AQID"),
    ]

    result = check_algorithm_rollover_readiness(dnskeys)

    assert result["ready"] is False
    assert result["missingAlgorithms"] == [13]


def test_ds_records_match_child_dnskey() -> None:
    zone = "example."
    key = DNSKEYRecord(owner=zone, flags=257, protocol=3, algorithm=8, public_key_b64="AQIDBAUG")
    digest = compute_ds_digest_hex(zone_name=zone, dnskey=key, digest_type=2)
    assert digest is not None

    ds = DSRecord(owner=zone, key_tag=dnskey_key_tag(key), algorithm=8, digest_type=2, digest_hex=digest)

    result = check_ds_dnskey_match(zone_name=zone, ds_records=[ds], dnskeys=[key])

    assert result["match"] is True
    assert result["mismatchedDsRecords"] == []


def test_ds_records_mismatch_child_dnskey() -> None:
    zone = "example."
    key = DNSKEYRecord(owner=zone, flags=257, protocol=3, algorithm=13, public_key_b64="AQIDBAUG")
    ds = DSRecord(owner=zone, key_tag=12345, algorithm=13, digest_type=2, digest_hex="DEADBEEF")

    result = check_ds_dnskey_match(zone_name=zone, ds_records=[ds], dnskeys=[key])

    assert result["match"] is False
    assert len(result["mismatchedDsRecords"]) == 1


def test_extract_and_map_error_tags_to_rst_codes() -> None:
    zonemaster_payload = {
        "results": [
            {"module": "DNSSEC", "tag": "DS02_NO_DNSKEY_FOR_DS"},
            {"module": "DNSSEC", "tag": "DNSSEC_INVALID_SIGNING_ALGORITHM"},
            {"module": "DNSSEC", "tag": "UNKNOWN_TAG"},
        ]
    }
    tags = extract_error_tags_from_zonemaster_output(zonemaster_payload)

    mapped = map_tags_to_rst_error_codes(
        tags,
        {
            "ZM_DS02_NO_DNSKEY_FOR_DS",
            "DNSSEC_INVALID_SIGNING_ALGORITHM",
            "DNSSEC_OPS_ALGORITHM_ROLLOVER_CHAIN_OF_TRUST_BROKEN",
        },
    )

    assert "ZM_DS02_NO_DNSKEY_FOR_DS" in mapped["matched"]
    assert "DNSSEC_INVALID_SIGNING_ALGORITHM" in mapped["matched"]
    assert "UNKNOWN_TAG" in mapped["unmatched"]
