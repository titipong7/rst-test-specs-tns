import json
import os
from pathlib import Path
from typing import Callable

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
    host = os.getenv("EPP_HOST")
    cert = os.getenv("EPP_CLIENT_CERT_FILE")
    key = os.getenv("EPP_CLIENT_KEY_FILE")
    if not host or not cert or not key:
        pytest.skip("EPP mTLS fixture requires EPP_HOST, EPP_CLIENT_CERT_FILE, and EPP_CLIENT_KEY_FILE")

    config = EppMtlsConfig(
        host=host,
        client_cert_file=Path(cert),
        client_key_file=Path(key),
        ca_cert_file=Path(os.environ["EPP_CA_BUNDLE_FILE"]) if os.getenv("EPP_CA_BUNDLE_FILE") else None,
        port=int(os.getenv("EPP_PORT", "700")),
        timeout_seconds=int(os.getenv("EPP_TIMEOUT_SECONDS", "30")),
        key_algorithm=os.getenv("EPP_KEY_ALGORITHM", "RSA"),
        key_size_bits=int(os.getenv("EPP_KEY_SIZE_BITS", "4096")),
    )
    client = EppClient(config=config)
    return client.send_epp_command
