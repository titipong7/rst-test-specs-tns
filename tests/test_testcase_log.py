from __future__ import annotations

import json
from pathlib import Path

from rst_compliance.testcase_log import TestCaseLog, write_testcase_log


def test_writes_testcaselog_compatible_json(tmp_path: Path) -> None:
    output = tmp_path / "logs" / "dns-01.json"
    log = TestCaseLog(
        testCaseId="dns-01",
        service="DNS",
        status="passed",
        startedAt="2026-04-01T00:00:00Z",
        finishedAt="2026-04-01T00:00:05Z",
        details={"runId": "abc-123"},
    )

    write_testcase_log(output_file=output, log=log)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["testCaseId"] == "dns-01"
    assert data["service"] == "DNS"
    assert data["status"] == "passed"
