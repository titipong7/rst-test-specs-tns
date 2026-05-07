"""
Root conftest.py – shared fixtures for the RST 2.0 API testing framework.

Configuration is loaded from environment variables or a YAML file placed at
``resources/config.yaml``.  A minimal example::

    epp:
      host: epp.example.com
      port: 700
      clid: clid-01
      pwd: secret
      tls_cert: resources/client.pem
      tls_key: resources/client.key

    rdap:
      base_urls:
        - tld: example
          baseURL: "https://rdap.example.com/example/"
      test_domains:
        - tld: example
          name: example.example
      test_nameservers:
        - tld: example
          nameserver: ns1.example.example
      test_entities:
        - tld: example
          handle: "9995"
"""

import os
import pathlib
import pytest
import yaml


CONFIG_PATH = pathlib.Path(__file__).parent / "resources" / "config.yaml"


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as fh:
            return yaml.safe_load(fh) or {}
    return {}


@pytest.fixture(scope="session")
def config() -> dict:
    """Return the full test configuration dictionary."""
    return _load_config()


@pytest.fixture(scope="session")
def epp_config(config) -> dict:
    """Return the EPP-specific section of the configuration."""
    return config.get("epp", {})


@pytest.fixture(scope="session")
def rdap_config(config) -> dict:
    """Return the RDAP-specific section of the configuration."""
    return config.get("rdap", {})
