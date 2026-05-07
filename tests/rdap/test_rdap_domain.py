"""
RDAP domain tests – RST 2.0 compliance.

Maps to RST test cases rdap-01, rdap-05, rdap-08 from inc/rdap/cases.yaml.
"""

from __future__ import annotations

import uuid
import logging

import pytest
import requests
from pydantic import ValidationError

from schemas.rdap.domain import RDAPDomainResponse
from schemas.rdap.common import RDAPError
from tests.rdap.conftest import DEFAULT_TIMEOUT, RDAP_CONTENT_TYPE

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.rdap


class TestRDAPDomainQuery:
    """rdap-01 – Domain query test."""

    def test_domain_query_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_domains: list[dict],
    ) -> None:
        """Each configured test domain MUST return HTTP 200."""
        if not rdap_test_domains:
            pytest.skip("rdap.test_domains not configured")

        for entry in rdap_test_domains:
            tld = entry["tld"]
            domain_name = entry["name"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                pytest.skip(f"No base URL configured for TLD '{tld}'")

            url = f"{base_url}domain/{domain_name}"
            logger.info("GET %s", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-01: Expected 200 for {url}, got {response.status_code}"
            )

    def test_domain_query_valid_content_type(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_domains: list[dict],
    ) -> None:
        """Response Content-Type MUST be application/rdap+json."""
        if not rdap_test_domains:
            pytest.skip("rdap.test_domains not configured")

        entry = rdap_test_domains[0]
        tld = entry["tld"]
        domain_name = entry["name"]
        base_url = next(
            (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
        )
        if base_url is None:
            pytest.skip(f"No base URL configured for TLD '{tld}'")

        url = f"{base_url}domain/{domain_name}"
        response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
        assert RDAP_CONTENT_TYPE in response.headers.get("Content-Type", ""), (
            f"Content-Type must contain '{RDAP_CONTENT_TYPE}'"
        )

    def test_domain_query_cors_header(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_domains: list[dict],
    ) -> None:
        """Response MUST include Access-Control-Allow-Origin header."""
        if not rdap_test_domains:
            pytest.skip("rdap.test_domains not configured")

        entry = rdap_test_domains[0]
        tld = entry["tld"]
        domain_name = entry["name"]
        base_url = next(
            (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
        )
        if base_url is None:
            pytest.skip(f"No base URL configured for TLD '{tld}'")

        url = f"{base_url}domain/{domain_name}"
        response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
        assert "access-control-allow-origin" in {
            k.lower() for k in response.headers
        }, "Missing Access-Control-Allow-Origin header"

    def test_domain_query_schema_validation(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_domains: list[dict],
    ) -> None:
        """Response body MUST validate against RDAPDomainResponse schema."""
        if not rdap_test_domains:
            pytest.skip("rdap.test_domains not configured")

        for entry in rdap_test_domains:
            tld = entry["tld"]
            domain_name = entry["name"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}domain/{domain_name}"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200

            try:
                parsed = RDAPDomainResponse.model_validate(response.json())
            except ValidationError as exc:
                pytest.fail(
                    f"rdap-01: RDAP_DOMAIN_RESPONSE_VALIDATION_FAILED for {domain_name}: {exc}"
                )

            assert parsed.ldhName or parsed.unicodeName, (
                "Domain response must have ldhName or unicodeName"
            )
            assert parsed.rdapConformance, (
                "Domain response must have rdapConformance"
            )
            assert parsed.has_registrar_entity(), (
                "Domain response must have an entity with role 'registrar'"
            )


class TestRDAPDomainHEAD:
    """rdap-05 – Domain HEAD test."""

    def test_domain_head_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_domains: list[dict],
    ) -> None:
        """HEAD requests for each test domain MUST return 200 with empty body."""
        if not rdap_test_domains:
            pytest.skip("rdap.test_domains not configured")

        for entry in rdap_test_domains:
            tld = entry["tld"]
            domain_name = entry["name"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}domain/{domain_name}"
            response = rdap_session.head(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-05: Expected 200 for HEAD {url}, got {response.status_code}"
            )
            assert len(response.content) == 0, (
                "HEAD response body must be empty"
            )
            assert "access-control-allow-origin" in {
                k.lower() for k in response.headers
            }, "HEAD response missing Access-Control-Allow-Origin"


class TestRDAPNonExistentDomain:
    """rdap-08 – Non-existent domain test."""

    def test_nonexistent_domain_returns_404(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """A query for a randomly generated domain MUST return HTTP 404."""
        for entry in rdap_base_urls:
            base_url = entry["baseURL"]
            tld = entry["tld"]
            random_name = f"nonexistent-{uuid.uuid4().hex}.{tld}"
            url = f"{base_url}domain/{random_name}"
            logger.info("GET %s (expecting 404)", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 404, (
                f"rdap-08: Expected 404 for non-existent domain, got {response.status_code}"
            )
            assert "access-control-allow-origin" in {
                k.lower() for k in response.headers
            }, "rdap-08: Missing Access-Control-Allow-Origin on 404 response"

            if response.content:
                try:
                    RDAPError.model_validate(response.json())
                except ValidationError as exc:
                    pytest.fail(
                        f"rdap-08: 404 body is not a valid RDAP error object: {exc}"
                    )
