"""
RDAP nameserver tests – RST 2.0 compliance.

Maps to RST test cases rdap-02, rdap-06, rdap-09 from inc/rdap/cases.yaml.
"""

from __future__ import annotations

import uuid
import logging

import pytest
import requests
from pydantic import ValidationError

from schemas.rdap.nameserver import RDAPNameserverResponse
from schemas.rdap.common import RDAPError
from tests.rdap.conftest import DEFAULT_TIMEOUT, RDAP_CONTENT_TYPE

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.rdap


class TestRDAPNameserverQuery:
    """rdap-02 – Nameserver query test."""

    def test_nameserver_query_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_nameservers: list[dict],
        epp_config: dict,
    ) -> None:
        """Each configured test nameserver MUST return HTTP 200."""
        if epp_config.get("host_model") == "attributes":
            pytest.skip("rdap-02: skipped because epp.hostModel is 'attributes'")
        if not rdap_test_nameservers:
            pytest.skip("rdap.test_nameservers not configured")

        for entry in rdap_test_nameservers:
            tld = entry["tld"]
            nameserver = entry["nameserver"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}nameserver/{nameserver}"
            logger.info("GET %s", url)
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-02: Expected 200 for {url}, got {response.status_code}"
            )

    def test_nameserver_query_schema_validation(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_nameservers: list[dict],
        epp_config: dict,
    ) -> None:
        """Response body MUST validate against RDAPNameserverResponse schema."""
        if epp_config.get("host_model") == "attributes":
            pytest.skip("rdap-02: skipped because epp.hostModel is 'attributes'")
        if not rdap_test_nameservers:
            pytest.skip("rdap.test_nameservers not configured")

        for entry in rdap_test_nameservers:
            tld = entry["tld"]
            nameserver = entry["nameserver"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}nameserver/{nameserver}"
            response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200

            try:
                parsed = RDAPNameserverResponse.model_validate(response.json())
            except ValidationError as exc:
                pytest.fail(
                    f"rdap-02: RDAP_NAMESERVER_RESPONSE_VALIDATION_FAILED "
                    f"for {nameserver}: {exc}"
                )

            assert parsed.ldhName, "Nameserver response must have ldhName"
            assert parsed.rdapConformance, (
                "Nameserver response must have rdapConformance"
            )


class TestRDAPNameserverHEAD:
    """rdap-06 – Nameserver HEAD test."""

    def test_nameserver_head_returns_200(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        rdap_test_nameservers: list[dict],
        epp_config: dict,
    ) -> None:
        """HEAD request for each test nameserver MUST return 200 with empty body."""
        if epp_config.get("host_model") == "attributes":
            pytest.skip("rdap-06: skipped because epp.hostModel is 'attributes'")
        if not rdap_test_nameservers:
            pytest.skip("rdap.test_nameservers not configured")

        for entry in rdap_test_nameservers:
            tld = entry["tld"]
            nameserver = entry["nameserver"]
            base_url = next(
                (u["baseURL"] for u in rdap_base_urls if u["tld"] == tld), None
            )
            if base_url is None:
                continue

            url = f"{base_url}nameserver/{nameserver}"
            response = rdap_session.head(url, timeout=DEFAULT_TIMEOUT)
            assert response.status_code == 200, (
                f"rdap-06: Expected 200 for HEAD {url}, got {response.status_code}"
            )
            assert len(response.content) == 0, "HEAD response body must be empty"
            assert "access-control-allow-origin" in {
                k.lower() for k in response.headers
            }, "HEAD response missing Access-Control-Allow-Origin"


class TestRDAPNonExistentNameserver:
    """rdap-09 – Non-existent nameserver test."""

    def test_nonexistent_nameserver_returns_404(
        self,
        rdap_session: requests.Session,
        rdap_base_urls: list[dict],
        epp_config: dict,
    ) -> None:
        """Queries for non-existent nameservers MUST return HTTP 404."""
        if epp_config.get("host_model") == "attributes":
            pytest.skip("rdap-09: skipped because epp.hostModel is 'attributes'")

        for entry in rdap_base_urls:
            base_url = entry["baseURL"]
            tld = entry["tld"]
            for suffix in [f".{tld}", ".external-ns-example.com"]:
                random_ns = f"ns-{uuid.uuid4().hex[:8]}{suffix}"
                url = f"{base_url}nameserver/{random_ns}"
                logger.info("GET %s (expecting 404)", url)
                response = rdap_session.get(url, timeout=DEFAULT_TIMEOUT)
                assert response.status_code == 404, (
                    f"rdap-09: Expected 404 for non-existent nameserver, "
                    f"got {response.status_code}"
                )
                if response.content:
                    try:
                        RDAPError.model_validate(response.json())
                    except ValidationError as exc:
                        pytest.fail(
                            f"rdap-09: 404 body is not a valid RDAP error object: {exc}"
                        )
