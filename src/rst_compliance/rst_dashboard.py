from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from rst_compliance.epp_connectivity import Epp01ProbeConfig, run_epp01_connectivity_probe
from rst_compliance.fips_check import check_hsm_fips_140_3_mode

SPEC_REFERENCE = "ICANN RST v2026.04"

CASE_ID_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:dns|dnssec|rdap|epp|rde|srsgw|idn|integration)"
    r"-(?:zz-[a-z0-9-]+|\d+)\b",
    re.IGNORECASE,
)
CASE_ID_PATTERNS: tuple[re.Pattern[str], ...] = (CASE_ID_PATTERN,)


def _extract_case_ids(text: str) -> set[str]:
    return {match for match in CASE_ID_PATTERN.findall(text)}



ETC_REQUIREMENTS = (
    {
        "id": "etc-index-links",
        "title": "etc/index.md exposes release and resource links",
        "file": "etc/index.md",
        "expected_tests": ("test_index_contains_required_release_and_resource_links",),
    },
    {
        "id": "etc-redirect-hash",
        "title": "etc/test-spec-redirect.html preserves location hash on redirect",
        "file": "etc/test-spec-redirect.html",
        "expected_tests": ("test_redirect_page_replaces_location_with_release_and_hash",),
    },
)
EPP_CASE_IDS = tuple(f"epp-{case_id:02d}" for case_id in range(1, 28))


@dataclass(frozen=True)
class DashboardPaths:
    repo_root: Path
    project_root: Path
    tests_root: Path
    schemas_root: Path
    reports_root: Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_paths(*, project_root: Path | None = None, repo_root: Path | None = None) -> DashboardPaths:
    effective_repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
    effective_project_root = (project_root or effective_repo_root / "internal-rst-checker").resolve()
    return DashboardPaths(
        repo_root=effective_repo_root,
        project_root=effective_project_root,
        tests_root=effective_project_root / "tests",
        schemas_root=effective_repo_root / "schemas",
        reports_root=effective_project_root / "reports",
    )


def ensure_layout(paths: DashboardPaths) -> None:
    paths.reports_root.mkdir(parents=True, exist_ok=True)


def discover_tests(*, tests_root: Path, modules: Sequence[str] | None = None) -> dict[str, list[str]]:
    module_filter = set(modules or [])
    discovered: dict[str, list[str]] = {}
    for path in sorted(tests_root.rglob("test_*.py")):
        relative = path.relative_to(tests_root)
        module = relative.parts[0] if len(relative.parts) > 1 else "tests"
        if module_filter and module not in module_filter:
            continue
        discovered.setdefault(module, []).append(str(relative))
    if module_filter:
        for module in modules or ():
            discovered.setdefault(module, [])
    return discovered


def map_spec_criteria(*, tests_root: Path, modules: Sequence[str] | None = None) -> list[dict[str, Any]]:
    module_filter = set(modules or [])
    mappings: list[dict[str, Any]] = []
    for path in sorted(tests_root.rglob("test_*.py")):
        relative = path.relative_to(tests_root)
        module = relative.parts[0] if len(relative.parts) > 1 else "tests"
        if module_filter and module not in module_filter:
            continue
        source = path.read_text(encoding="utf-8")
        parsed = ast.parse(source)
        for node in parsed.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                labels = _extract_case_ids(node.name)
                docstring = ast.get_docstring(node)
                if docstring:
                    labels.update(_extract_case_ids(docstring))
                mappings.append(
                    {
                        "testName": node.name,
                        "file": str(relative),
                        "module": module,
                        "rstSpecVersion": SPEC_REFERENCE,
                        "criteriaIds": sorted(label.lower() for label in labels),
                    }
                )
    return mappings


def summarize_schemas(*, schemas_root: Path) -> dict[str, Any]:
    json_files = sorted(str(path.relative_to(schemas_root)) for path in schemas_root.rglob("*.json"))
    xsd_files = sorted(str(path.relative_to(schemas_root)) for path in schemas_root.rglob("*.xsd"))
    return {
        "json_count": len(json_files),
        "xsd_count": len(xsd_files),
        "json_files": json_files,
        "xsd_files": xsd_files,
    }


def summarize_etc_requirement_coverage(
    *,
    spec_mapping: list[dict[str, Any]],
    case_results: list[dict[str, Any]],
) -> dict[str, Any]:
    case_status_by_name: dict[str, list[str]] = {}
    for result in case_results:
        node_id = str(result.get("testCase", ""))
        if "::" not in node_id:
            continue
        test_name = node_id.rsplit("::", 1)[-1]
        case_status_by_name.setdefault(test_name, []).append(str(result.get("status", "")).lower())

    requirements: list[dict[str, str]] = []
    for requirement in ETC_REQUIREMENTS:
        expected_tests = set(requirement["expected_tests"])
        matched_tests = {
            entry["testName"]
            for entry in spec_mapping
            if entry.get("module") == "etc" and entry.get("testName") in expected_tests
        }
        if not matched_tests:
            status = "missing"
            reason = "No etc smoke test is mapped for this requirement."
        elif not case_results:
            status = "partial"
            reason = "Test exists but execution was skipped (dry-run or no junit results)."
        else:
            statuses = [
                state
                for name in matched_tests
                for key, values in case_status_by_name.items()
                if key == name or key.startswith(f"{name}[")
                for state in values
            ]
            if not statuses:
                status = "partial"
                reason = "Test is mapped but no execution result was found in junit output."
            elif all(state == "pass" for state in statuses):
                status = "covered"
                reason = "Mapped etc smoke tests passed."
            else:
                status = "partial"
                reason = "At least one mapped etc smoke test did not pass."

        requirements.append(
            {
                "id": str(requirement["id"]),
                "title": str(requirement["title"]),
                "file": str(requirement["file"]),
                "status": status,
                "reason": reason,
            }
        )

    status_totals = {"covered": 0, "partial": 0, "missing": 0}
    for item in requirements:
        status_totals[item["status"]] = status_totals.get(item["status"], 0) + 1

    return {
        "requirements": requirements,
        "summary": status_totals,
    }


DEFAULT_SUITES: tuple[str, ...] = (
    "dns",
    "dnssec",
    "dnssec-ops",
    "epp",
    "idn",
    "integration",
    "rdap",
    "rde",
    "srsgw",
)

# Map a case_id back to the 2-character on-disk prefix used by the flat
# fixture layout (`<NN>-<slug>-{success,failure}.<ext>`). The default rule
# is "trailing digits of the case_id, zero-padded to two characters"; suites
# whose `case_id`s do not encode a numeric prefix override that via this table.
_DNS_PREFIX_OVERRIDES = {
    "dns-zz-idna2008-compliance": "01",
    "dns-zz-consistency": "02",
}
_DNSSEC_OPS_PREFIX_OVERRIDES = {
    "dnssecOps01-ZSKRollover": "01",
    "dnssecOps02-KSKRollover": "02",
    "dnssecOps03-AlgorithmRollover": "03",
}
SUITE_CASE_PREFIX: dict[str, dict[str, str]] = {
    "dns": _DNS_PREFIX_OVERRIDES,
    "dnssec-ops": _DNSSEC_OPS_PREFIX_OVERRIDES,
}


def _case_prefix(suite: str, case_id: str) -> str | None:
    """Return the 2-char fixture prefix for a case_id, or None when unknown."""
    overrides = SUITE_CASE_PREFIX.get(suite, {})
    if case_id in overrides:
        return overrides[case_id]
    digits = re.findall(r"\d+", case_id)
    if not digits:
        return None
    return digits[-1].zfill(2)


_TOP_LEVEL_YAML_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*):\s*$")


def _read_top_level_keys(yaml_path: Path) -> list[str]:
    """Minimalist YAML loader: return top-level keys preserving order.

    The dashboard only needs the flat `case_id` / `error_code` keys from
    `inc/<suite>/{cases,errors}.yaml`, which are guaranteed to be top-level
    in this spec version. Avoids a runtime dependency on PyYAML so the
    dashboard runs in minimal CI images.
    """
    if not yaml_path.is_file():
        return []
    keys: list[str] = []
    for raw_line in yaml_path.read_text(encoding="utf-8").splitlines():
        match = _TOP_LEVEL_YAML_KEY.match(raw_line)
        if match:
            keys.append(match.group(1))
    return keys


def load_active_case_ids(suite: str, inc_root: Path) -> tuple[str, ...]:
    """Read `<inc_root>/<suite>/cases.yaml` and return its ordered case_id keys."""
    return tuple(_read_top_level_keys(inc_root / suite / "cases.yaml"))


def _read_case_maturity_from_yaml(yaml_path: Path) -> dict[str, str]:
    if not yaml_path.is_file():
        return {}
    out: dict[str, str] = {}
    current: str | None = None
    maturity_pattern = re.compile(r"^  Maturity:\s+(\S+)\s*$")
    for raw_line in yaml_path.read_text(encoding="utf-8").splitlines():
        key = _TOP_LEVEL_YAML_KEY.match(raw_line)
        if key:
            current = key.group(1)
            out.setdefault(current, "UNKNOWN")
            continue
        if current is None:
            continue
        mm = maturity_pattern.match(raw_line)
        if mm:
            out[current] = mm.group(1).upper()
    return out


def rollup_maturity(cases_yaml_path: Path) -> dict[str, int]:
    """Aggregate Maturity counts from one ``cases.yaml`` file.

    Returns a dict shaped like ``{"GAMMA": n, "BETA": n, "ALPHA": n,
    "UNKNOWN": n, "total": n}``.
    """
    by_case = _read_case_maturity_from_yaml(cases_yaml_path)
    counts: dict[str, int] = {}
    for level in by_case.values():
        key = (level or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = sum(counts.values())
    return counts


def load_case_maturity(suite: str, *, repo_root: Path) -> dict[str, str]:
    """Return `{case_id: Maturity}` for every case in `inc/<suite>/cases.yaml`.

    Missing or absent `Maturity:` lines map to ``"UNKNOWN"``.
    """
    return _read_case_maturity_from_yaml(repo_root / "inc" / suite / "cases.yaml")


def _case_status_index(case_results: list[dict[str, Any]]) -> dict[str, list[str]]:
    by_name: dict[str, list[str]] = {}
    for result in case_results:
        node_id = str(result.get("testCase", ""))
        if "::" not in node_id:
            continue
        test_name = node_id.rsplit("::", 1)[-1]
        by_name.setdefault(test_name, []).append(str(result.get("status", "")).lower())
    return by_name


def _matched_tests_for_case(
    *,
    suite: str,
    case_id: str,
    spec_mapping: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    module_alias = "dnssec_ops" if suite == "dnssec-ops" else suite
    needle = case_id.lower()
    matches: list[dict[str, Any]] = []
    for entry in spec_mapping:
        criteria = [str(value).lower() for value in entry.get("criteriaIds", [])]
        if needle not in criteria:
            continue
        module = str(entry.get("module", ""))
        if module not in (suite, module_alias):
            continue
        matches.append(entry)
    return matches


def summarize_suite_coverage(
    suite: str,
    *,
    spec_mapping: list[dict[str, Any]],
    case_results: list[dict[str, Any]],
    active_case_ids: Sequence[str],
) -> dict[str, Any]:
    """Coverage matrix for one suite, generalised from the legacy EPP variant."""
    case_status_by_name = _case_status_index(case_results)

    matrix: list[dict[str, Any]] = []
    for case_id in active_case_ids:
        if suite == "epp" and case_id == "epp-22":
            matrix.append(
                {
                    "caseId": case_id,
                    "status": "partial",
                    "reason": "Removed from v2026.04 StandardEPP but kept in matrix for continuity.",
                    "tests": [],
                }
            )
            continue

        matched_tests = _matched_tests_for_case(
            suite=suite, case_id=case_id, spec_mapping=spec_mapping
        )
        if not matched_tests:
            matrix.append(
                {
                    "caseId": case_id,
                    "status": "missing",
                    "reason": "No mapped internal checker test.",
                    "tests": [],
                }
            )
            continue

        mapped_names = [str(item["testName"]) for item in matched_tests]
        if not case_results:
            matrix.append(
                {
                    "caseId": case_id,
                    "status": "partial",
                    "reason": "Mapped test exists but no execution results were provided.",
                    "tests": mapped_names,
                }
            )
            continue

        statuses = [
            state
            for name in mapped_names
            for key, values in case_status_by_name.items()
            if key == name or key.startswith(f"{name}[")
            for state in values
        ]
        if statuses and "pass" in statuses and all(state in {"pass", "skipped"} for state in statuses):
            status = "covered"
            reason = "Mapped tests passed (with optional variants skipped where not applicable)."
        elif statuses:
            status = "partial"
            reason = "Mapped tests exist but at least one did not pass."
        else:
            status = "partial"
            reason = "Mapped tests not present in junit results."

        matrix.append(
            {
                "caseId": case_id,
                "status": status,
                "reason": reason,
                "tests": mapped_names,
            }
        )

    summary = {"covered": 0, "partial": 0, "missing": 0}
    for item in matrix:
        summary[item["status"]] = summary.get(item["status"], 0) + 1
    return {"matrix": matrix, "summary": summary}


def summarize_epp_suite_coverage(
    *,
    spec_mapping: list[dict[str, Any]],
    case_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Backwards-compatible wrapper preserved for the legacy `eppSuiteCoverage` key."""
    return summarize_suite_coverage(
        "epp",
        spec_mapping=spec_mapping,
        case_results=case_results,
        active_case_ids=EPP_CASE_IDS,
    )


def summarize_all_suite_coverage(
    *,
    repo_root: Path,
    spec_mapping: list[dict[str, Any]],
    case_results: list[dict[str, Any]],
    suites: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run `summarize_suite_coverage` for every in-scope suite."""
    target_suites = tuple(suites) if suites else DEFAULT_SUITES
    inc_root = repo_root / "inc"
    out: dict[str, Any] = {}
    for suite in target_suites:
        case_ids: tuple[str, ...] = (
            EPP_CASE_IDS if suite == "epp" else load_active_case_ids(suite, inc_root)
        )
        if not case_ids:
            continue
        out[suite] = summarize_suite_coverage(
            suite,
            spec_mapping=spec_mapping,
            case_results=case_results,
            active_case_ids=case_ids,
        )
    return out


_FIXTURE_SUFFIXES_TEXT_LIKE = {".txt", ".example"}


def _fixture_parses(path: Path) -> bool:
    """Return True if the fixture's payload parses with the format-appropriate loader."""
    try:
        body = path.read_bytes()
    except OSError:
        return False
    if not body:
        return False
    suffix = path.suffix.lower()
    try:
        if suffix == ".xml":
            ET.fromstring(body)
            return True
        if suffix == ".json":
            json.loads(body.decode("utf-8"))
            return True
        if suffix == ".csv":
            import csv

            for _ in csv.reader(body.decode("utf-8").splitlines()):
                pass
            return True
        if suffix in {".asc", ".gpg"}:
            return b"-----BEGIN PGP" in body
        # Fallback for `.ryde.example`, `.txt`, `.env.example`, etc.
        return True
    except (ET.ParseError, ValueError, UnicodeDecodeError):
        return False


def _fixture_iter(fixtures_root: Path, suite: str) -> list[Path]:
    """Return every fixture file under a suite folder, sorted, ignoring README/dirs."""
    suite_root = fixtures_root / suite
    if not suite_root.is_dir():
        return []
    items: list[Path] = []
    for path in suite_root.iterdir():
        if not path.is_file():
            continue
        if path.name == "README.md":
            continue
        if path.suffix == ".md":
            continue
        items.append(path)
    return sorted(items, key=lambda p: p.name)


def _split_th_subfolder(fixtures_root: Path) -> list[tuple[str, Path]]:
    """EPP fixtures live under `fixtures/epp/th/`; report that pair when present."""
    pairs: list[tuple[str, Path]] = []
    th_dir = fixtures_root / "epp" / "th"
    if th_dir.is_dir():
        pairs.append(("epp", th_dir))
    return pairs


def scan_fixture_inventory(
    fixtures_root: Path,
    suite: str,
    *,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Inventory the on-disk fixtures for one suite, bucketed by case_id.

    ``repo_root`` is consulted to read the suite's ``cases.yaml`` so the
    inventory rows can be correlated with the spec's active case_ids; when
    omitted it falls back to two parents up from ``fixtures_root`` (the
    standard internal-rst-checker layout).
    """
    effective_repo_root = repo_root or fixtures_root.parent.parent
    inc_root = effective_repo_root / "inc"

    if suite == "epp":
        epp_files: list[Path] = []
        for _name, folder in _split_th_subfolder(fixtures_root):
            epp_files.extend(
                p for p in folder.iterdir() if p.is_file() and p.suffix != ".md"
            )
        files = sorted(epp_files, key=lambda p: p.name)
    else:
        files = _fixture_iter(fixtures_root, suite)
    if not files:
        return []

    case_ids: tuple[str, ...] = (
        EPP_CASE_IDS if suite == "epp" else load_active_case_ids(suite, inc_root)
    )

    by_prefix: dict[str, list[Path]] = {}
    for fixture in files:
        prefix = fixture.name[:2]
        by_prefix.setdefault(prefix, []).append(fixture)

    suite_rows: list[dict[str, Any]] = []
    seen_prefixes: set[str] = set()
    for case_id in case_ids:
        prefix = _case_prefix(suite, case_id)
        if not prefix:
            continue
        matched = sorted(by_prefix.get(prefix, []), key=lambda p: p.name)
        seen_prefixes.add(prefix)
        if not matched:
            continue
        suite_rows.append(
            {
                "caseId": case_id,
                "files": [p.name for p in matched],
                "parses": {p.name: _fixture_parses(p) for p in matched},
            }
        )
    unmapped_files = [p for p in files if p.name[:2] not in seen_prefixes]
    if unmapped_files:
        suite_rows.append(
            {
                "caseId": None,
                "files": [p.name for p in unmapped_files],
                "parses": {p.name: _fixture_parses(p) for p in unmapped_files},
            }
        )
    return suite_rows


def summarize_fixture_inventory(
    *,
    fixtures_root: Path,
    repo_root: Path,
    suites: Sequence[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Run ``scan_fixture_inventory`` for every in-scope suite."""
    target_suites = tuple(suites) if suites else DEFAULT_SUITES
    inventory: dict[str, list[dict[str, Any]]] = {}
    for suite in target_suites:
        rows = scan_fixture_inventory(fixtures_root, suite, repo_root=repo_root)
        if rows:
            inventory[suite] = rows
    return inventory


def summarize_maturity_rollup(
    *,
    suite: str,
    case_maturity: dict[str, str],
) -> dict[str, int]:
    """Bucket a `{case_id: level}` map into numeric per-level counts."""
    _ = suite  # accepted for symmetry with other summarizers; not used numerically.
    counts: dict[str, int] = {}
    for level in case_maturity.values():
        key = (level or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def summarize_all_maturity(
    *,
    repo_root: Path,
    suites: Sequence[str] | None = None,
) -> dict[str, dict[str, int]]:
    """Run `rollup_maturity` for every in-scope suite."""
    target_suites = tuple(suites) if suites else DEFAULT_SUITES
    out: dict[str, dict[str, int]] = {}
    for suite in target_suites:
        cases_yaml = repo_root / "inc" / suite / "cases.yaml"
        if not cases_yaml.is_file():
            continue
        rollup = rollup_maturity(cases_yaml)
        if rollup.get("total", 0) > 0:
            out[suite] = rollup
    return out


def run_pytest(*, repo_root: Path, test_files: Sequence[Path], html_report: Path, junit_report: Path) -> dict[str, Any]:
    if not test_files:
        return {
            "status": "skipped",
            "returncode": 0,
            "command": [],
            "stdout": "No tests discovered under tests/.",
            "stderr": "",
            "htmlReport": str(html_report),
            "junitReport": str(junit_report),
        }

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        *[str(path) for path in test_files],
        "--html",
        str(html_report),
        "--self-contained-html",
        "--junitxml",
        str(junit_report),
    ]
    env = os.environ.copy()
    pythonpath_entries = [str(repo_root / "src")]
    if env.get("PYTHONPATH"):
        pythonpath_entries.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)

    completed = subprocess.run(
        command,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return {
        "status": "passed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "htmlReport": str(html_report),
        "junitReport": str(junit_report),
    }


def _normalize_reason(raw_reason: str | None, raw_text: str | None) -> str:
    reason = (raw_reason or "").strip()
    if reason:
        return reason.splitlines()[0]
    text = (raw_text or "").strip()
    if not text:
        return "-"
    return text.splitlines()[0]


def parse_junit_report(*, report_file: Path) -> list[dict[str, Any]]:
    if not report_file.exists():
        return []

    root = ET.fromstring(report_file.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = []
    for testcase in root.iter("testcase"):
        class_name = testcase.attrib.get("classname", "")
        test_name = testcase.attrib.get("name", "")
        node_id = f"{class_name}::{test_name}" if class_name else test_name
        status = "pass"
        reason = "-"
        detail = None
        for fail_tag, fail_status in (("failure", "fail"), ("error", "error"), ("skipped", "skipped")):
            node = testcase.find(fail_tag)
            if node is not None:
                status = fail_status
                reason = _normalize_reason(node.attrib.get("message"), node.text)
                detail = (node.text or "").strip()
                break
        cases.append(
            {
                "testCase": node_id,
                "status": status,
                "reason": reason,
                "durationSeconds": float(testcase.attrib.get("time", "0")),
                "details": detail,
            }
        )
    return cases


def _truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


def render_terminal_table(case_results: list[dict[str, Any]]) -> str:
    headers = ("Test Case", "Status", "Reason")
    widths = (60, 8, 80)
    separator = f"+-{'-' * widths[0]}-+-{'-' * widths[1]}-+-{'-' * widths[2]}-+"
    lines = [
        separator,
        f"| {headers[0]:<{widths[0]}} | {headers[1]:<{widths[1]}} | {headers[2]:<{widths[2]}} |",
        separator,
    ]
    for result in case_results:
        lines.append(
            "| "
            f"{_truncate(str(result['testCase']), widths[0]):<{widths[0]}} | "
            f"{_truncate(str(result['status']), widths[1]):<{widths[1]}} | "
            f"{_truncate(str(result['reason']), widths[2]):<{widths[2]}} |"
        )
    lines.append(separator)
    return "\n".join(lines)


def render_placeholder_html(summary: dict[str, Any]) -> str:
    rows = "\n".join(
        f"<tr><td>{case['testCase']}</td><td>{case['status']}</td><td>{case['reason']}</td></tr>"
        for case in summary["caseResults"]
    ) or "<tr><td colspan='3'>No test cases</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>RST Dashboard Report</title></head>
<body>
  <h1>RST Internal Dashboard</h1>
  <p>Generated: {summary["generatedAt"]}</p>
  <p>Status: {summary["run"]["status"]}</p>
  <table border="1" cellspacing="0" cellpadding="6">
    <thead><tr><th>Test Case</th><th>Status</th><th>Reason</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""


def build_summary(
    *,
    paths: DashboardPaths,
    discovered_tests: dict[str, list[str]],
    spec_mapping: list[dict[str, Any]],
    schema_summary: dict[str, Any],
    etc_requirement_coverage: dict[str, Any],
    epp_suite_coverage: dict[str, Any],
    run_summary: dict[str, Any],
    case_results: list[dict[str, Any]],
    fips_summary: dict[str, Any],
    epp01_connectivity: dict[str, Any],
    suite_coverage: dict[str, Any] | None = None,
    maturity_summary: dict[str, Any] | None = None,
    fixture_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "generatedAt": _now_iso(),
        "repoRoot": str(paths.repo_root),
        "projectRoot": str(paths.project_root),
        "testsRoot": str(paths.tests_root),
        "schemasRoot": str(paths.schemas_root),
        "reportsRoot": str(paths.reports_root),
        "rstSpecVersion": SPEC_REFERENCE,
        "discoveredTests": discovered_tests,
        "testFileCount": sum(len(files) for files in discovered_tests.values()),
        "specMapping": spec_mapping,
        "schemaInventory": schema_summary,
        "etcRequirementCoverage": etc_requirement_coverage,
        "eppSuiteCoverage": epp_suite_coverage,
        "suiteCoverage": suite_coverage or {},
        "fixtureInventory": fixture_inventory or {},
        "maturitySummary": maturity_summary or {},
        "epp01Connectivity": epp01_connectivity,
        "fipsCheck": fips_summary,
        "caseResults": case_results,
        "run": run_summary,
    }


def write_report_files(
    *,
    summary: dict[str, Any],
    reports_root: Path,
    json_report: Path | None = None,
) -> Path:
    effective_json_report = json_report or reports_root / "report.json"
    effective_json_report.parent.mkdir(parents=True, exist_ok=True)
    effective_json_report.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return effective_json_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run internal RST checks and write dashboard summaries")
    parser.add_argument("--module", action="append", help="Limit execution to one or more module folders")
    parser.add_argument("--repo-root", type=Path, help="Repository root path")
    parser.add_argument("--tests-root", type=Path, help="Override tests root path")
    parser.add_argument("--schemas-root", type=Path, help="Override schemas root path")
    parser.add_argument("--reports-dir", type=Path, help="Override reports output directory")
    parser.add_argument("--json-report", type=Path, help="Optional JSON report file path")
    parser.add_argument("--html-report", type=Path, help="Optional HTML report file path")
    parser.add_argument(
        "--suite",
        action="append",
        help=(
            "Limit suiteCoverage / fixtureInventory / maturitySummary to the "
            "named suites. Repeatable; default = every default suite with "
            "cases.yaml on disk."
        ),
    )
    parser.add_argument(
        "--skip-fixtures",
        action="store_true",
        help="Skip the on-disk fixture inventory walk",
    )
    parser.add_argument("--dry-run", action="store_true", help="Prepare reports without running pytest")
    parser.add_argument("--live-epp01", action="store_true", help="Run live connectivity checks for epp-01")
    parser.add_argument("--epp-host", help="Override EPP host for epp-01 live checks")
    parser.add_argument("--epp-port", type=int, default=700, help="Override EPP port for epp-01 live checks")
    return parser


def main(argv: Sequence[str] | None = None, *, project_root: Path | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    base_paths = resolve_paths(project_root=project_root, repo_root=args.repo_root)
    paths = DashboardPaths(
        repo_root=base_paths.repo_root,
        project_root=base_paths.project_root,
        tests_root=args.tests_root.resolve() if args.tests_root else base_paths.tests_root,
        schemas_root=args.schemas_root.resolve() if args.schemas_root else base_paths.schemas_root,
        reports_root=args.reports_dir.resolve() if args.reports_dir else base_paths.reports_root,
    )
    modules = tuple(args.module or ())

    ensure_layout(paths)
    discovered_tests = discover_tests(tests_root=paths.tests_root, modules=modules or None)
    spec_mapping = map_spec_criteria(tests_root=paths.tests_root, modules=modules or None)
    schema_summary = summarize_schemas(schemas_root=paths.schemas_root)
    fips_summary = check_hsm_fips_140_3_mode()

    test_paths = [paths.tests_root / relative_path for files in discovered_tests.values() for relative_path in files]
    html_report = args.html_report.resolve() if args.html_report else paths.reports_root / "report.html"
    junit_report = paths.reports_root / "report-junit.xml"

    run_summary = (
        {
            "status": "not-run",
            "returncode": 0,
            "command": [],
            "stdout": "Dry run: pytest execution skipped.",
            "stderr": "",
            "htmlReport": str(html_report),
            "junitReport": str(junit_report),
        }
        if args.dry_run
        else run_pytest(
            repo_root=paths.repo_root,
            test_files=test_paths,
            html_report=html_report,
            junit_report=junit_report,
        )
    )

    case_results = [] if args.dry_run else parse_junit_report(report_file=junit_report)
    if case_results:
        print(render_terminal_table(case_results))
    etc_requirement_coverage = summarize_etc_requirement_coverage(
        spec_mapping=spec_mapping,
        case_results=case_results,
    )
    epp_suite_coverage = summarize_epp_suite_coverage(
        spec_mapping=spec_mapping,
        case_results=case_results,
    )
    epp_host = args.epp_host or os.environ.get("EPP_HOST")
    if args.live_epp01 and epp_host:
        epp01_connectivity = run_epp01_connectivity_probe(
            Epp01ProbeConfig(
                host=epp_host,
                port=args.epp_port,
            )
        ).to_dict()
        epp01_connectivity["mode"] = "live"
    else:
        epp01_connectivity = {
            "mode": "not-run",
            "status": "not-run",
            "reason": "Live epp-01 probe disabled or EPP host not provided.",
        }

    suites_filter = tuple(args.suite) if args.suite else None
    suite_coverage = summarize_all_suite_coverage(
        repo_root=paths.repo_root,
        spec_mapping=spec_mapping,
        case_results=case_results,
        suites=suites_filter,
    )
    fixtures_root = paths.project_root / "fixtures"
    fixture_inventory = (
        {}
        if args.skip_fixtures
        else summarize_fixture_inventory(
            fixtures_root=fixtures_root,
            repo_root=paths.repo_root,
            suites=suites_filter,
        )
    )
    maturity_summary = summarize_all_maturity(
        repo_root=paths.repo_root,
        suites=suites_filter,
    )

    summary = build_summary(
        paths=paths,
        discovered_tests=discovered_tests,
        spec_mapping=spec_mapping,
        schema_summary=schema_summary,
        etc_requirement_coverage=etc_requirement_coverage,
        epp_suite_coverage=epp_suite_coverage,
        run_summary=run_summary,
        case_results=case_results,
        fips_summary=fips_summary,
        epp01_connectivity=epp01_connectivity,
        suite_coverage=suite_coverage,
        fixture_inventory=fixture_inventory,
        maturity_summary=maturity_summary,
    )
    write_report_files(
        summary=summary,
        reports_root=paths.reports_root,
        json_report=args.json_report.resolve() if args.json_report else None,
    )
    if args.dry_run and not html_report.exists():
        html_report.parent.mkdir(parents=True, exist_ok=True)
        html_report.write_text(render_placeholder_html(summary), encoding="utf-8")
    return int(run_summary["returncode"])


if __name__ == "__main__":
    raise SystemExit(main())
