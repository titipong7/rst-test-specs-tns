import json
import os
from pathlib import Path
from typing import Callable
from unittest.mock import MagicMock

import pytest

from rst_compliance.config import JSON_SCHEMA_PATH, XML_SCHEMA_PATH
from rst_compliance.epp_client import EppClient, EppMtlsConfig


@pytest.fixture
def schema_dirs(tmp_path: Path) -> tuple[Path, Path]:
    json_dir = tmp_path / JSON_SCHEMA_PATH
    xml_dir = tmp_path / XML_SCHEMA_PATH
    json_dir.mkdir(parents=True, exist_ok=True)
    xml_dir.mkdir(parents=True, exist_ok=True)

    testcase_log_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["testCaseId", "service", "status", "startedAt", "finishedAt"],
        "properties": {
            "testCaseId": {"type": "string"},
            "service": {"type": "string"},
            "status": {"type": "string", "enum": ["passed", "failed", "error", "running"]},
            "startedAt": {"type": "string"},
            "finishedAt": {"type": "string"},
            "details": {"type": "object"},
        },
    }
    (json_dir / "testCaseLog.schema.json").write_text(json.dumps(testcase_log_schema), encoding="utf-8")

    epp_xsd = """<?xml version=\"1.0\"?>
    <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">
      <xs:element name=\"epp\" type=\"xs:string\"/>
    </xs:schema>
    """
    (xml_dir / "epp-response.xsd").write_text(epp_xsd, encoding="utf-8")

    return json_dir, xml_dir


@pytest.fixture
def send_epp_command() -> Callable[[str], str]:
    """Return a callable that sends a single EPP XML command over mTLS.

    Reads connection parameters from environment variables::

        EPP_HOST     – EPP server hostname (required to run live)
        EPP_CERT     – path to client certificate PEM file (required to run live)
        EPP_KEY      – path to client key PEM file (required to run live)
        EPP_CA_CERT  – path to CA certificate PEM file (optional)
        EPP_PORT     – EPP server port (default: 700)

    If ``EPP_HOST``, ``EPP_CERT`` or ``EPP_KEY`` are unset the fixture skips
    the calling test, allowing the suite to run without a live EPP endpoint.
    """
    host = os.getenv("EPP_HOST", "")
    cert = os.getenv("EPP_CERT", "")
    key = os.getenv("EPP_KEY", "")

    if not host or not cert or not key:
        pytest.skip("EPP_HOST, EPP_CERT and EPP_KEY environment variables are required for live EPP tests")

    ca_cert_path = os.getenv("EPP_CA_CERT")
    port = int(os.getenv("EPP_PORT", "700"))

    config = EppMtlsConfig(
        host=host,
        client_cert_file=Path(cert),
        client_key_file=Path(key),
        ca_cert_file=Path(ca_cert_path) if ca_cert_path else None,
        port=port,
        key_algorithm="RSA",
        key_size_bits=4096,
    )
    client = EppClient(config=config)

    return client.send_command
