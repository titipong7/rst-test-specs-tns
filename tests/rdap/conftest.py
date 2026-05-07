"""
RDAP conftest – provides an HTTP session fixture pre-configured for RDAP.

The ``rdap_session`` fixture yields a :class:`requests.Session` with:
  - default ``Accept: application/rdap+json`` header
  - connection/read timeouts
  - TLS verification enabled

Configuration is read from the ``rdap`` section of ``resources/config.yaml``.
"""

from __future__ import annotations

import logging
from typing import Generator

import pytest
import requests

logger = logging.getLogger(__name__)

RDAP_CONTENT_TYPE = "application/rdap+json"
DEFAULT_TIMEOUT = (10, 30)  # (connect, read) seconds


@pytest.fixture(scope="module")
def rdap_session() -> Generator[requests.Session, None, None]:
    """Yield a reusable requests.Session configured for RDAP queries."""
    session = requests.Session()
    session.headers.update({"Accept": RDAP_CONTENT_TYPE})
    yield session
    session.close()


@pytest.fixture(scope="module")
def rdap_base_urls(rdap_config: dict) -> list[dict]:
    """Return the list of RDAP base URL objects from config."""
    urls = rdap_config.get("base_urls", [])
    if not urls:
        pytest.skip("rdap.base_urls not configured")
    return urls


@pytest.fixture(scope="module")
def rdap_test_domains(rdap_config: dict) -> list[dict]:
    return rdap_config.get("test_domains", [])


@pytest.fixture(scope="module")
def rdap_test_nameservers(rdap_config: dict) -> list[dict]:
    return rdap_config.get("test_nameservers", [])


@pytest.fixture(scope="module")
def rdap_test_entities(rdap_config: dict) -> list[dict]:
    return rdap_config.get("test_entities", [])
