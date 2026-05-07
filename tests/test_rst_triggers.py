from __future__ import annotations

from typing import Any

import pytest

from rst_compliance.client import RstApiClient
from rst_compliance.config import RstApiConfig


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self):
        self.last_call: dict[str, Any] = {}

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str], timeout: int) -> _FakeResponse:
        self.last_call = {"url": url, "json": json, "headers": headers, "timeout": timeout}
        return _FakeResponse({"triggered": True, "service": json["service"], "testCaseId": json["testCaseId"]})


@pytest.mark.parametrize("service", ["DNS", "DNSSEC", "RDAP", "EPP"])
def test_trigger_endpoint_for_rsp_services(service: str) -> None:
    session = _FakeSession()
    client = RstApiClient(RstApiConfig(base_url="https://rst.example.test", auth_token="token-123"), session=session)

    result = client.trigger_test_case(service=service, test_case_id=f"{service.lower()}-01", params={"registry": "example"})

    assert result["triggered"] is True
    assert result["service"] == service
    assert session.last_call["url"].endswith("/v2/tests/trigger")
    assert session.last_call["json"]["testCaseId"] == f"{service.lower()}-01"
    assert session.last_call["headers"]["Authorization"].startswith("Bearer ")
