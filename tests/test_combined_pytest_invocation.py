"""Regression test for review finding Info-1.

Asserts that the combined invocation
``pytest internal-rst-checker/tests tests``
collects without raising a duplicate-basename ``import file mismatch``.

The collision used to fire on ``test_dnssec_zone_health.py``,
``test_epp_host_constraints.py``, and ``test_rdap_conformance.py`` because
both ``tests/`` and ``internal-rst-checker/tests/<suite>/`` contained files
with the same basenames and pytest's default ``prepend`` import mode put
both copies under the same ``__file__``.

The project-wide ``import-mode = "importlib"`` setting in
``pyproject.toml`` resolves this. This test runs ``pytest --collect-only``
as a subprocess so it exercises the real config loader.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COLLIDING_BASENAMES: tuple[str, ...] = (
    "test_dnssec_zone_health.py",
    "test_epp_host_constraints.py",
    "test_rdap_conformance.py",
)


def _both_roots_have_collision() -> bool:
    flat = REPO_ROOT / "tests"
    nested = REPO_ROOT / "internal-rst-checker" / "tests"
    if not flat.is_dir() or not nested.is_dir():
        return False
    nested_basenames = {p.name for p in nested.rglob("test_*.py")}
    flat_basenames = {p.name for p in flat.glob("test_*.py")}
    return any(name in flat_basenames and name in nested_basenames for name in COLLIDING_BASENAMES)


@pytest.mark.skipif(
    not _both_roots_have_collision(),
    reason="repository layout no longer has the duplicate-basename collision Info-1 guards against",
)
def test_combined_pytest_invocation_collects_without_collision(tmp_path: Path) -> None:
    """Info-1: pytest can collect both roots in one invocation."""
    # Defensive: a stale `__pycache__` from a legacy ``prepend``-mode run can
    # still poison a fresh invocation, so wipe project pycache before probing.
    for cache in REPO_ROOT.rglob("__pycache__"):
        if ".venv" in cache.parts:
            continue
        shutil.rmtree(cache, ignore_errors=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "internal-rst-checker/tests",
            "tests",
            "--collect-only",
            "-q",
            "--no-header",
            f"--rootdir={REPO_ROOT}",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    combined_output = completed.stdout + completed.stderr
    assert completed.returncode == 0, (
        f"combined pytest invocation failed (rc={completed.returncode}):\n"
        f"--- stdout ---\n{completed.stdout}\n--- stderr ---\n{completed.stderr}"
    )
    assert "import file mismatch" not in combined_output, (
        "duplicate-basename collision regression detected:\n" + combined_output
    )
    assert "errors during collection" not in combined_output, (
        "pytest collection errors detected:\n" + combined_output
    )
