"""Tests for the RST v2.0 lifecycle state machine (lifecycle.py).

Covers RST test case phases:
  rst-01 (create), rst-02 (submit), rst-03 (poll), rst-04 (retrieve)
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from rst_compliance.config import RstApiConfig
from rst_compliance.lifecycle import (
    LifecycleError,
    LifecycleState,
    RstLifecycleClient,
    TestLifecycle,
    _extract_error_tags,
)


# ---------------------------------------------------------------------------
# TestLifecycle state-machine unit tests
# ---------------------------------------------------------------------------


def test_lifecycle_initial_state_is_created() -> None:
    lc = TestLifecycle(test_id="t-001")
    assert lc.state == LifecycleState.CREATED


def test_lifecycle_full_happy_path_transitions() -> None:
    lc = TestLifecycle(test_id="t-001")
    lc.mark_submitted()
    assert lc.state == LifecycleState.SUBMITTED
    lc.mark_running()
    assert lc.state == LifecycleState.RUNNING
    lc.mark_completed({"status": "completed"})
    assert lc.state == LifecycleState.COMPLETED


def test_lifecycle_mark_submitted_raises_from_wrong_state() -> None:
    lc = TestLifecycle(test_id="t-001")
    lc.mark_submitted()
    lc.mark_running()
    with pytest.raises(LifecycleError, match="submitted"):
        lc.mark_submitted()


def test_lifecycle_mark_failed_sets_state() -> None:
    lc = TestLifecycle(test_id="t-001")
    lc.mark_submitted()
    lc.mark_running()
    lc.mark_failed({"status": "failed"})
    assert lc.state == LifecycleState.FAILED


def test_lifecycle_mark_completed_populates_result() -> None:
    lc = TestLifecycle(test_id="t-001")
    lc.mark_submitted()
    lc.mark_running()
    lc.mark_completed({"status": "completed", "data": "ok"})
    assert lc.result == {"status": "completed", "data": "ok"}


# ---------------------------------------------------------------------------
# _extract_error_tags
# ---------------------------------------------------------------------------


def test_extract_error_tags_finds_error_severity() -> None:
    result = {
        "testResults": [
            {"tag": "DNSSEC_MISSING_DS", "severity": "ERROR"},
            {"tag": "EPP_TIMEOUT", "severity": "CRITICAL"},
            {"tag": "RDAP_LATENCY_OK", "severity": "INFO"},
        ]
    }
    tags = _extract_error_tags(result)
    assert "DNSSEC_MISSING_DS" in tags
    assert "EPP_TIMEOUT" in tags
    assert "RDAP_LATENCY_OK" not in tags


def test_extract_error_tags_handles_nested_structures() -> None:
    result = {
        "group": {
            "nested": {"tag": "DNS_BAD_ALGO", "severity": "CRITICAL"},
        }
    }
    tags = _extract_error_tags(result)
    assert "DNS_BAD_ALGO" in tags


def test_extract_error_tags_returns_empty_for_clean_result() -> None:
    result = {"status": "completed", "passed": True}
    assert _extract_error_tags(result) == []


# ---------------------------------------------------------------------------
# RstLifecycleClient – integration-style tests with mock sessions
# ---------------------------------------------------------------------------


def _make_response(payload: dict[str, Any], status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = payload
    resp.status_code = status_code
    resp.raise_for_status.return_value = None
    return resp


def _config() -> RstApiConfig:
    return RstApiConfig(base_url="https://rst.example.test", auth_token="tok-abc")


def test_create_test_object_returns_lifecycle_with_test_id() -> None:
    session = MagicMock()
    session.post.return_value = _make_response({"testId": "run-999"})
    client = RstLifecycleClient(_config(), session=session)

    lc = client.create_test_object(test_plan="StandardPreDelegationTest", tld="example", service="DNS")

    assert lc.test_id == "run-999"
    assert lc.state == LifecycleState.CREATED


def test_submit_inputs_transitions_to_submitted() -> None:
    session = MagicMock()
    session.post.return_value = _make_response({"accepted": True})
    client = RstLifecycleClient(_config(), session=session)
    lc = TestLifecycle(test_id="run-999")

    client.submit_inputs(lc, input_parameters={"dns.tld": "example"})

    assert lc.state == LifecycleState.SUBMITTED


def test_poll_until_complete_handles_completed_status() -> None:
    session = MagicMock()
    session.get.return_value = _make_response({"status": "completed", "testId": "run-999"})
    client = RstLifecycleClient(_config(), session=session, poll_interval_seconds=0)
    lc = TestLifecycle(test_id="run-999", state=LifecycleState.SUBMITTED)

    client.poll_until_complete(lc)

    assert lc.state == LifecycleState.COMPLETED


def test_poll_until_complete_handles_failed_status() -> None:
    session = MagicMock()
    session.get.return_value = _make_response({"status": "failed", "testId": "run-999"})
    client = RstLifecycleClient(_config(), session=session, poll_interval_seconds=0)
    lc = TestLifecycle(test_id="run-999", state=LifecycleState.SUBMITTED)

    client.poll_until_complete(lc)

    assert lc.state == LifecycleState.FAILED


def test_poll_until_complete_raises_after_max_attempts() -> None:
    session = MagicMock()
    session.get.return_value = _make_response({"status": "running"})
    client = RstLifecycleClient(
        _config(), session=session, poll_interval_seconds=0, max_poll_attempts=2
    )
    lc = TestLifecycle(test_id="run-999", state=LifecycleState.SUBMITTED)

    with pytest.raises(LifecycleError, match="poll attempts"):
        client.poll_until_complete(lc)


def test_retrieve_results_returns_results_payload() -> None:
    session = MagicMock()
    session.get.return_value = _make_response({"results": [{"tag": "DNS_OK"}]})
    client = RstLifecycleClient(_config(), session=session)
    lc = TestLifecycle(test_id="run-999", state=LifecycleState.COMPLETED)

    results = client.retrieve_results(lc)

    assert results == {"results": [{"tag": "DNS_OK"}]}


def test_retrieve_results_raises_when_not_terminal() -> None:
    session = MagicMock()
    client = RstLifecycleClient(_config(), session=session)
    lc = TestLifecycle(test_id="run-999", state=LifecycleState.RUNNING)

    with pytest.raises(LifecycleError, match="running"):
        client.retrieve_results(lc)


def test_run_full_lifecycle_end_to_end() -> None:
    session = MagicMock()
    session.post.return_value = _make_response({"testId": "run-999"})
    get_responses = [
        _make_response({"status": "running"}),
        _make_response({"status": "completed"}),
    ]
    session.get.side_effect = get_responses + [_make_response({"results": []})]
    client = RstLifecycleClient(_config(), session=session, poll_interval_seconds=0)

    lc, results = client.run_full_lifecycle(
        test_plan="StandardPreDelegationTest",
        tld="example",
        service="DNS",
        input_parameters={"dns.tld": "example"},
    )

    assert lc.state == LifecycleState.COMPLETED
    assert results == {"results": []}
