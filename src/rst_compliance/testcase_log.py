from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class TestCaseLog:
    testCaseId: str
    service: str
    status: str
    startedAt: str
    finishedAt: str
    details: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_testcase_log(*, output_file: Path, log: TestCaseLog) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(log.to_dict(), indent=2), encoding="utf-8")
