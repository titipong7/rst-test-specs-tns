import json
from pathlib import Path

import pytest

from rst_compliance.config import JSON_SCHEMA_PATH, XML_SCHEMA_PATH


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
