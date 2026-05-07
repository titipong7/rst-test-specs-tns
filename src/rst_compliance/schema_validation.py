from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate
from xmlschema import XMLSchema


def validate_json_payload(*, schema_file: Path, payload: dict) -> None:
    with schema_file.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validate(instance=payload, schema=schema)


def validate_xml_payload(*, schema_file: Path, xml_text: str) -> None:
    schema = XMLSchema(str(schema_file))
    schema.validate(xml_text)
