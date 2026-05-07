from dataclasses import dataclass
from pathlib import Path


SCHEMA_BASE_PATH = Path("schemas") / "rst-api-spec" / "v2026.4"
JSON_SCHEMA_PATH = SCHEMA_BASE_PATH / "json"
XML_SCHEMA_PATH = SCHEMA_BASE_PATH / "xml"


@dataclass(frozen=True)
class RstApiConfig:
    base_url: str
    auth_token: str | None = None
    timeout_seconds: int = 30
