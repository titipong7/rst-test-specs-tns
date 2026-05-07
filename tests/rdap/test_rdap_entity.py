"""
RDAP entity tests – RST 2.0 compliance.

Maps to RST test cases rdap-03, rdap-07, rdap-10 from inc/rdap/cases.yaml.
"""

from __future__ import annotations

import uuid
import logging

import pytest
import requests
from pydantic import ValidationError

from schemas.rdap.entity import RDAPEntityResponse
from schemas.rdap.common import RDAPError
from tests.rdap.conftest import DEFAULT_TIMEOUT, RDAP_CONTENT_TYPE

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.rdap


class TestRDAPEntityQuery:
    """rdap-03 – Registrar (entity) query test."""

    def test_entity_query_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_entities: list[dict],
    ) -> None:
        """Each configured test entity MUST return HTTP 200."""
        if not rdap_test_entities:
            pytest.skip("rdap.test_entities not configured")

        for entry in rdap_test_entities:
            tld = entry["tld"]
            handle = entry["handle"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}entity/{handle}"
            logger.info("GET %s", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-03: Expected 200 for {url}, got {response.status_code}"
            )

    def test_entity_query_schema_validation(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_entities: list[dict],
    ) -> None:
        """Response body MUST validate against RDAPEntityResponse schema."""
        if not rdap_test_entities:
            pytest.skip("rdap.test_entities not configured")

        for entry in rdap_test_entities:
            tld = entry["tld"]
            handle = entry["handle"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}entity/{handle}"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200

            try:
                parsed = RDAPEntityResponse.model_validate(response.json())
            except ValidationError as exc:
                pytest.fail(
                    f"rdap-03: RDAP_ENTITY_RESPONSE_VALIDATION_FAILED "
                    f"for handle '{handle}': {exc}"
                )

            assert parsed.rdapConformance, (
                "Entity response must have rdapConformance"
            )


class TestRDAPEntityHEAD:
    """rdap-07 – Entity HEAD test."""

    def test_entity_head_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_entities: list[dict],
    ) -> None:
        """HEAD request for each test entity MUST return 200 with empty body."""
        if not rdap_test_entities:
            pytest.skip("rdap.test_entities not configured")

        for entry in rdap_test_entities:
            tld = entry["tld"]
            handle = entry["handle"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}entity/{handle}"
            response = rdap_session.head(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-07: Expected 200 for HEAD {url}, got {response.status_code}"
            )
            assert len(response.content) == 0, "HEAD response body must be empty"
            assert "access-control-allow-origin" in {
                k.lower() for k in response.headers
            }, "HEAD response missing Access-Control-Allow-Origin"


class TestRDAPNonExistentEntity:
    """rdap-10 – Non-existent entity test."""

    def test_nonexistent_entity_returns_404(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """A query for a randomly generated entity handle MUST return HTTP 404."""
        for entry in rdap_base_urls:
            base_url = entry["baseURL"]
            random_handle = f"NONEXISTENT-{uuid.uuid4().hex.upper()}"
            url = f"{base_url}entity/{random_handle}"
            logger.info("GET %s (expecting 404)", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 404, (
                f"rdap-10: Expected 404 for non-existent entity, "
                f"got {response.status_code}"
            )
            if response.content:
                try:
                    RDAPError.model_validate(response.json())
                except ValidationError as exc:
                    pytest.fail(
                        f"rdap-10: 404 body is not a valid RDAP error object: {exc}"
                    )
