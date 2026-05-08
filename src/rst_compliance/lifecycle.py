"""RST v2.0 lifecycle state machine.

Implements the four-phase test lifecycle defined by the ICANN RST v2.0 API:

  Create Test Object → Submit Input Parameters → Poll Status → Retrieve Results
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests

from rst_compliance.config import RstApiConfig


class LifecycleState(str, Enum):
    CREATED = "created"
    SUBMITTED = "submitted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"


class LifecycleError(RuntimeError):
    """Raised when the RST lifecycle reaches an unexpected state."""


@dataclass
class TestLifecycle:
    """Tracks a single RST test object through its full lifecycle."""

    __test__ = False

    test_id: str
    state: LifecycleState = LifecycleState.CREATED
    result: dict[str, Any] | None = None
    error_tags: list[str] = field(default_factory=list)

    def _transition(self, expected: LifecycleState, new_state: LifecycleState) -> None:
        if self.state != expected:
            raise LifecycleError(
                f"Cannot transition from {self.state!r} to {new_state!r}: "
                f"expected current state {expected!r}"
            )
        self.state = new_state

    def mark_submitted(self) -> None:
        self._transition(LifecycleState.CREATED, LifecycleState.SUBMITTED)

    def mark_running(self) -> None:
        self._transition(LifecycleState.SUBMITTED, LifecycleState.RUNNING)

    def mark_completed(self, result: dict[str, Any]) -> None:
        if self.state not in {LifecycleState.RUNNING, LifecycleState.SUBMITTED}:
            raise LifecycleError(
                f"Cannot mark completed from state {self.state!r}"
            )
        self.state = LifecycleState.COMPLETED
        self.result = result
        self.error_tags = _extract_error_tags(result)

    def mark_failed(self, result: dict[str, Any] | None = None) -> None:
        self.state = LifecycleState.FAILED
        if result is not None:
            self.result = result
            self.error_tags = _extract_error_tags(result)


def _extract_error_tags(result: dict[str, Any]) -> list[str]:
    """Extract ERROR or CRITICAL severity tags from a test result payload."""
    tags: list[str] = []
    _collect_tags(result, tags)
    return tags


def _collect_tags(value: Any, tags: list[str]) -> None:
    if isinstance(value, dict):
        severity = value.get("severity", "")
        tag = value.get("tag")
        if isinstance(severity, str) and severity.upper() in {"ERROR", "CRITICAL"} and isinstance(tag, str):
            tags.append(tag)
        for nested in value.values():
            _collect_tags(nested, tags)
    elif isinstance(value, list):
        for item in value:
            _collect_tags(item, tags)


class RstLifecycleClient:
    """Drives the full RST v2.0 test lifecycle against the RST API.

    Phase 1 – Create Test Object  : POST /v2/tests
    Phase 2 – Submit Input JSON   : POST /v2/tests/{id}/inputs
    Phase 3 – Poll Status         : GET  /v2/tests/{id}
    Phase 4 – Retrieve Results    : GET  /v2/tests/{id}/results
    """

    _TERMINAL_STATES = {"completed", "failed", "error"}

    def __init__(
        self,
        config: RstApiConfig,
        session: requests.Session | None = None,
        poll_interval_seconds: int = 10,
        max_poll_attempts: int = 60,
    ) -> None:
        self.config = config
        self.session = session or requests.Session()
        self.poll_interval_seconds = poll_interval_seconds
        self.max_poll_attempts = max_poll_attempts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base(self) -> str:
        return self.config.base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        return headers

    def _get(self, url: str) -> dict[str, Any]:
        response = self.session.get(url, headers=self._headers(), timeout=self.config.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            url, json=payload, headers=self._headers(), timeout=self.config.timeout_seconds
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Lifecycle phases
    # ------------------------------------------------------------------

    def create_test_object(
        self,
        *,
        test_plan: str,
        tld: str,
        service: str,
    ) -> TestLifecycle:
        """Phase 1 – Create a new test object and return a lifecycle tracker."""
        payload = {"testPlan": test_plan, "tld": tld, "service": service}
        data = self._post(f"{self._base()}/v2/tests", payload)
        test_id: str = data.get("testId") or data.get("id") or str(data)
        return TestLifecycle(test_id=test_id, state=LifecycleState.CREATED)

    def submit_inputs(
        self,
        lifecycle: TestLifecycle,
        *,
        input_parameters: dict[str, Any],
    ) -> None:
        """Phase 2 – Submit input parameters JSON for the test object."""
        lifecycle.mark_submitted()
        self._post(f"{self._base()}/v2/tests/{lifecycle.test_id}/inputs", input_parameters)

    def poll_until_complete(self, lifecycle: TestLifecycle) -> None:
        """Phase 3 – Poll the test status until it reaches a terminal state."""
        lifecycle.mark_running()
        for _ in range(self.max_poll_attempts):
            data = self._get(f"{self._base()}/v2/tests/{lifecycle.test_id}")
            status: str = (data.get("status") or "").lower()
            if status in self._TERMINAL_STATES:
                if status == "completed":
                    lifecycle.mark_completed(data)
                else:
                    lifecycle.mark_failed(data)
                return
            time.sleep(self.poll_interval_seconds)

        raise LifecycleError(
            f"Test {lifecycle.test_id!r} did not reach a terminal state "
            f"after {self.max_poll_attempts} poll attempts."
        )

    def retrieve_results(self, lifecycle: TestLifecycle) -> dict[str, Any]:
        """Phase 4 – Retrieve the final results for a completed test."""
        if lifecycle.state not in {LifecycleState.COMPLETED, LifecycleState.FAILED}:
            raise LifecycleError(
                f"Cannot retrieve results: test is in state {lifecycle.state!r}. "
                "Ensure poll_until_complete() has been called first."
            )
        data = self._get(f"{self._base()}/v2/tests/{lifecycle.test_id}/results")
        return data

    def run_full_lifecycle(
        self,
        *,
        test_plan: str,
        tld: str,
        service: str,
        input_parameters: dict[str, Any],
    ) -> tuple[TestLifecycle, dict[str, Any]]:
        """Convenience method: runs all four lifecycle phases end-to-end."""
        lifecycle = self.create_test_object(test_plan=test_plan, tld=tld, service=service)
        self.submit_inputs(lifecycle, input_parameters=input_parameters)
        self.poll_until_complete(lifecycle)
        results = self.retrieve_results(lifecycle)
        return lifecycle, results
