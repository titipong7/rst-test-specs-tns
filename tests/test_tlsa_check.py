"""Tests for the TLSA/DANE verification module (tlsa_check.py).

Covers RST API security requirement: mTLS with TLSA record verification
per RFC 6698 (DANE), as required by the ICANN RST v2.0 automated security layer.
"""
from __future__ import annotations

import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from rst_compliance.tlsa_check import (
    MATCHING_SHA256,
    MATCHING_SHA512,
    SELECTOR_FULL_CERT,
    SELECTOR_SPKI,
    TlsaRecord,
    TlsaVerificationError,
    compute_tlsa_association_data,
    load_cert_from_pem,
    parse_tlsa_record,
    verify_cert_against_tlsa,
    verify_tlsa_records,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_cert_and_pem() -> tuple[x509.Certificate, bytes]:
    """Generate a minimal self-signed RSA certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rst-test.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, pem


# ---------------------------------------------------------------------------
# TlsaRecord parsing
# ---------------------------------------------------------------------------


def test_tlsa_record_from_text_parses_four_fields() -> None:
    tlsa = TlsaRecord.from_text("3 1 1 abcdef1234567890")
    assert tlsa.usage == 3
    assert tlsa.selector == 1
    assert tlsa.matching_type == 1
    assert tlsa.certificate_association_data == "abcdef1234567890"


def test_tlsa_record_from_text_raises_on_missing_fields() -> None:
    with pytest.raises(TlsaVerificationError, match="4 fields"):
        TlsaRecord.from_text("3 1 1")


def test_tlsa_record_from_text_raises_on_non_integer_fields() -> None:
    with pytest.raises(TlsaVerificationError, match="integers"):
        TlsaRecord.from_text("X 1 1 abcdef")


def test_tlsa_record_from_dict_parses_correctly() -> None:
    tlsa = TlsaRecord.from_dict(
        {"usage": 3, "selector": 1, "matching_type": 1, "certificate_association_data": "AABBCC"}
    )
    assert tlsa.usage == 3
    assert tlsa.certificate_association_data == "aabbcc"


def test_parse_tlsa_record_dispatches_to_text_for_str() -> None:
    tlsa = parse_tlsa_record("3 1 1 deadbeef")
    assert tlsa.usage == 3


def test_parse_tlsa_record_dispatches_to_dict_for_dict() -> None:
    tlsa = parse_tlsa_record(
        {"usage": 2, "selector": 0, "matching_type": 2, "certificate_association_data": "cafe"}
    )
    assert tlsa.usage == 2


# ---------------------------------------------------------------------------
# compute_tlsa_association_data
# ---------------------------------------------------------------------------


def test_compute_association_data_sha256_selector_spki(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, _ = rsa_cert_and_pem
    der_spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected = hashlib.sha256(der_spki).hexdigest()

    result = compute_tlsa_association_data(cert, selector=SELECTOR_SPKI, matching_type=MATCHING_SHA256)

    assert result == expected


def test_compute_association_data_sha512_selector_full_cert(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, _ = rsa_cert_and_pem
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    expected = hashlib.sha512(der_cert).hexdigest()

    result = compute_tlsa_association_data(cert, selector=SELECTOR_FULL_CERT, matching_type=MATCHING_SHA512)

    assert result == expected


def test_compute_association_data_raises_on_unsupported_selector(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, _ = rsa_cert_and_pem
    with pytest.raises(TlsaVerificationError, match="selector"):
        compute_tlsa_association_data(cert, selector=99, matching_type=MATCHING_SHA256)


# ---------------------------------------------------------------------------
# verify_cert_against_tlsa
# ---------------------------------------------------------------------------


def test_verify_cert_against_tlsa_passes_on_correct_data(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, _ = rsa_cert_and_pem
    correct_data = compute_tlsa_association_data(
        cert, selector=SELECTOR_SPKI, matching_type=MATCHING_SHA256
    )
    tlsa = TlsaRecord(
        usage=3,
        selector=SELECTOR_SPKI,
        matching_type=MATCHING_SHA256,
        certificate_association_data=correct_data,
    )
    verify_cert_against_tlsa(cert, tlsa)  # must not raise


def test_verify_cert_against_tlsa_raises_on_wrong_data(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, _ = rsa_cert_and_pem
    tlsa = TlsaRecord(
        usage=3,
        selector=SELECTOR_SPKI,
        matching_type=MATCHING_SHA256,
        certificate_association_data="0" * 64,
    )
    with pytest.raises(TlsaVerificationError, match="does not match"):
        verify_cert_against_tlsa(cert, tlsa)


# ---------------------------------------------------------------------------
# verify_tlsa_records (batch)
# ---------------------------------------------------------------------------


def test_verify_tlsa_records_returns_pass_for_correct_record(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    cert, pem = rsa_cert_and_pem
    correct_data = compute_tlsa_association_data(
        cert, selector=SELECTOR_SPKI, matching_type=MATCHING_SHA256
    )
    tlsa_text = f"3 1 1 {correct_data}"

    results = verify_tlsa_records(pem, [tlsa_text])

    assert len(results) == 1
    assert results[0]["status"] == "pass"


def test_verify_tlsa_records_returns_fail_for_wrong_record(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    _, pem = rsa_cert_and_pem
    results = verify_tlsa_records(pem, [f"3 1 1 {'0' * 64}"])

    assert results[0]["status"] == "fail"
    assert "does not match" in results[0]["reason"]


def test_load_cert_from_pem_returns_certificate(
    rsa_cert_and_pem: tuple[x509.Certificate, bytes],
) -> None:
    _, pem = rsa_cert_and_pem
    cert = load_cert_from_pem(pem)
    assert isinstance(cert, x509.Certificate)
