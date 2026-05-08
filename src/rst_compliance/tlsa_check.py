"""TLSA record (DANE) verification for ICANN RST v2.0 mTLS authentication.

Validates TLSA DNS records and verifies that a presented X.509 certificate
matches the TLSA record according to RFC 6698 (DANE) and the ICANN RST v2.0
automated security layer requirements.

Supported TLSA selectors and matching types:
  - Selector 0 (Full certificate) / Selector 1 (SubjectPublicKeyInfo)
  - Matching type 1 (SHA-256) / Matching type 2 (SHA-512)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization


# TLSA field constants (RFC 6698)
USAGE_PKIX_TA = 0
USAGE_PKIX_EE = 1
USAGE_DANE_TA = 2
USAGE_DANE_EE = 3

SELECTOR_FULL_CERT = 0
SELECTOR_SPKI = 1

MATCHING_EXACT = 0
MATCHING_SHA256 = 1
MATCHING_SHA512 = 2


class TlsaVerificationError(ValueError):
    """Raised when TLSA verification fails."""


@dataclass(frozen=True)
class TlsaRecord:
    """Parsed TLSA DNS record (RFC 6698 §2.1).

    Attributes:
        usage:         Certificate usage field (0-3).
        selector:      Selector field (0 = full cert, 1 = SPKI).
        matching_type: Matching type field (0 = exact, 1 = SHA-256, 2 = SHA-512).
        certificate_association_data: Hex-encoded association data.
    """

    usage: int
    selector: int
    matching_type: int
    certificate_association_data: str

    @classmethod
    def from_text(cls, record: str) -> "TlsaRecord":
        """Parse a TLSA record from its presentation format.

        Example: ``3 1 1 abc123...``
        """
        parts = record.strip().split()
        if len(parts) < 4:
            raise TlsaVerificationError(
                f"TLSA record must have at least 4 fields (usage selector matching data), "
                f"got {len(parts)} fields: {record!r}"
            )
        try:
            usage, selector, matching_type = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError as exc:
            raise TlsaVerificationError(f"TLSA numeric fields are not integers: {record!r}") from exc
        return cls(
            usage=usage,
            selector=selector,
            matching_type=matching_type,
            certificate_association_data=parts[3].lower(),
        )

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "TlsaRecord":
        """Parse a TLSA record from a dictionary (e.g. from a DNS library)."""
        return cls(
            usage=int(record["usage"]),
            selector=int(record["selector"]),
            matching_type=int(record["matching_type"]),
            certificate_association_data=str(record["certificate_association_data"]).lower(),
        )


def _cert_material(cert: x509.Certificate, selector: int) -> bytes:
    """Return the raw bytes to hash/compare based on the TLSA selector."""
    if selector == SELECTOR_SPKI:
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    if selector == SELECTOR_FULL_CERT:
        return cert.public_bytes(serialization.Encoding.DER)
    raise TlsaVerificationError(f"Unsupported TLSA selector: {selector}")


def _hash_material(data: bytes, matching_type: int) -> str:
    """Return the hex-encoded digest of data for the given matching type."""
    if matching_type == MATCHING_SHA256:
        return hashlib.sha256(data).hexdigest()
    if matching_type == MATCHING_SHA512:
        return hashlib.sha512(data).hexdigest()
    if matching_type == MATCHING_EXACT:
        return data.hex()
    raise TlsaVerificationError(f"Unsupported TLSA matching type: {matching_type}")


def compute_tlsa_association_data(cert: x509.Certificate, *, selector: int, matching_type: int) -> str:
    """Compute the TLSA certificate association data for a given certificate.

    Args:
        cert:          Parsed X.509 certificate.
        selector:      TLSA selector (0 = full cert, 1 = SPKI).
        matching_type: TLSA matching type (1 = SHA-256, 2 = SHA-512, 0 = exact).

    Returns:
        Lowercase hex string of the association data.
    """
    material = _cert_material(cert, selector)
    return _hash_material(material, matching_type)


def verify_cert_against_tlsa(
    cert: x509.Certificate,
    tlsa_record: TlsaRecord,
) -> None:
    """Verify that *cert* matches the given *tlsa_record*.

    Raises:
        TlsaVerificationError: if the certificate does not match the TLSA record.
    """
    computed = compute_tlsa_association_data(
        cert,
        selector=tlsa_record.selector,
        matching_type=tlsa_record.matching_type,
    )
    expected = tlsa_record.certificate_association_data.lower()
    if computed != expected:
        raise TlsaVerificationError(
            f"Certificate does not match TLSA record "
            f"(usage={tlsa_record.usage}, selector={tlsa_record.selector}, "
            f"matching_type={tlsa_record.matching_type}): "
            f"computed={computed!r}, expected={expected!r}"
        )


def parse_tlsa_record(record: dict[str, Any] | str) -> TlsaRecord:
    """Parse a TLSA record from either a presentation string or a dict."""
    if isinstance(record, str):
        return TlsaRecord.from_text(record)
    return TlsaRecord.from_dict(record)


def load_cert_from_pem(pem_data: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM-encoded bytes."""
    return x509.load_pem_x509_certificate(pem_data)


def verify_tlsa_records(
    cert_pem: bytes,
    tlsa_records: list[dict[str, Any] | str],
) -> list[dict[str, Any]]:
    """Verify a certificate against a list of TLSA records.

    Returns a list of result dicts, one per TLSA record.  Each dict has:
      - ``record``: the parsed TlsaRecord fields
      - ``status``: ``"pass"`` or ``"fail"``
      - ``reason``: human-readable explanation
    """
    cert = load_cert_from_pem(cert_pem)
    results: list[dict[str, Any]] = []

    for raw_record in tlsa_records:
        try:
            tlsa = parse_tlsa_record(raw_record)
            verify_cert_against_tlsa(cert, tlsa)
            results.append(
                {
                    "record": {
                        "usage": tlsa.usage,
                        "selector": tlsa.selector,
                        "matching_type": tlsa.matching_type,
                        "certificate_association_data": tlsa.certificate_association_data,
                    },
                    "status": "pass",
                    "reason": "Certificate matches TLSA record",
                }
            )
        except TlsaVerificationError as exc:
            record_info = raw_record if isinstance(raw_record, str) else str(raw_record)
            results.append(
                {
                    "record": record_info,
                    "status": "fail",
                    "reason": str(exc),
                }
            )

    return results
