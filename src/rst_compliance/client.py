from __future__ import annotations

from typing import Any

import requests

from rst_compliance.config import RstApiConfig


class RstApiClient:
    """Minimal RST 2.0 client for automated trigger calls."""

    def __init__(self, config: RstApiConfig, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()

    def trigger_test_case(self, *, service: str, test_case_id: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        endpoint = f"{self.config.base_url.rstrip('/')}/v2/tests/trigger"
        payload = {
            "service": service,
            "testCaseId": test_case_id,
            "parameters": params or {},
        }
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"

        response = self.session.post(endpoint, json=payload, headers=headers, timeout=self.config.timeout_seconds)
        response.raise_for_status()
        return response.json()
