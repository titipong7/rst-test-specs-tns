"""
RDAP help tests – RST 2.0 compliance.

Maps to RST test case rdap-04 from inc/rdap/cases.yaml.
"""

from __future__ import annotations

import logging

import pytest
import requests
from pydantic import ValidationError

from schemas.rdap.help import RDAPHelpResponse
from tests.rdap.conftest import DEFAULT_TIMEOUT, RDAP_CONTENT_TYPE

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.rdap


class TestRDAPHelp:
    """rdap-04 – Help query test."""

    def test_help_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """A /help query MUST return HTTP 200 for each base URL."""
        for entry in rdap_base_urls:
            url = f"{entry['baseURL']}help"
            logger.info("GET %s", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-04: Expected 200 for {url}, got {response.status_code}"
            )

    def test_help_content_type(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """Help response Content-Type MUST be application/rdap+json."""
        for entry in rdap_base_urls:
            url = f"{entry['baseURL']}help"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert RDAP_CONTENT_TYPE in response.headers.get("Content-Type", ""), (
                f"Content-Type must contain '{RDAP_CONTENT_TYPE}'"
            )

    def test_help_cors_header(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """Help response MUST include Access-Control-Allow-Origin."""
        for entry in rdap_base_urls:
            url = f"{entry['baseURL']}help"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert "access-control-allow-origin" in {
                k.lower() for k in response.headers
            }, f"Missing Access-Control-Allow-Origin for {url}"

    def test_help_schema_validation(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
    ) -> None:
        """Help response body MUST validate against RDAPHelpResponse schema."""
        for entry in rdap_base_urls:
            url = f"{entry['baseURL']}help"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200

            try:
                parsed = RDAPHelpResponse.model_validate(response.json())
            except ValidationError as exc:
                pytest.fail(
                    f"rdap-04: RDAP_HELP_RESPONSE_VALIDATION_FAILED for {url}: {exc}"
                )

            assert parsed.rdapConformance, (
                "Help response must have rdapConformance"
            )
