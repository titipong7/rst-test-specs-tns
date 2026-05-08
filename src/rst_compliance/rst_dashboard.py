from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

DEFAULT_MODULES = ("epp", "rdap", "dns")


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
        schemas_root=effective_project_root / "schemas",
        reports_root=effective_project_root / "reports",
    )


def ensure_layout(paths: DashboardPaths, modules: Sequence[str] = DEFAULT_MODULES) -> None:
    for module in modules:
        (paths.tests_root / module).mkdir(parents=True, exist_ok=True)
    for schema_dir in ("json", "xml"):
        (paths.schemas_root / schema_dir).mkdir(parents=True, exist_ok=True)
    paths.reports_root.mkdir(parents=True, exist_ok=True)


def discover_tests(*, tests_root: Path, modules: Sequence[str] = DEFAULT_MODULES) -> dict[str, list[str]]:
    discovered: dict[str, list[str]] = {}
    for module in modules:
        module_root = tests_root / module
        files = sorted(str(path.relative_to(tests_root)) for path in module_root.rglob("test_*.py"))
        discovered[module] = files
    return discovered


def summarize_schemas(*, schemas_root: Path) -> dict[str, Any]:
    json_files = sorted(str(path.relative_to(schemas_root)) for path in schemas_root.rglob("*.json"))
    xsd_files = sorted(str(path.relative_to(schemas_root)) for path in schemas_root.rglob("*.xsd"))
    return {
        "json_count": len(json_files),
        "xsd_count": len(xsd_files),
        "json_files": json_files,
        "xsd_files": xsd_files,
    }


def run_pytest(*, repo_root: Path, test_files: Sequence[Path]) -> dict[str, Any]:
    if not test_files:
        return {
            "status": "skipped",
            "returncode": 0,
            "command": [],
            "stdout": "No tests discovered under internal-rst-checker/tests.",
            "stderr": "",
        }

    command = [sys.executable, "-m", "pytest", "-q", *[str(path) for path in test_files]]
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
    }


def build_summary(
    *,
    paths: DashboardPaths,
    modules: Sequence[str],
    discovered_tests: dict[str, list[str]],
    schema_summary: dict[str, Any],
    run_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "generatedAt": _now_iso(),
        "repoRoot": str(paths.repo_root),
        "projectRoot": str(paths.project_root),
        "testsRoot": str(paths.tests_root),
        "schemasRoot": str(paths.schemas_root),
        "reportsRoot": str(paths.reports_root),
        "modules": list(modules),
        "discoveredTests": discovered_tests,
        "testFileCount": sum(len(files) for files in discovered_tests.values()),
        "schemaInventory": schema_summary,
        "run": run_summary,
    }


def render_html_report(summary: dict[str, Any]) -> str:
    discovered_rows = "\n".join(
        f"<tr><th>{html.escape(module)}</th><td>{len(files)}</td><td>{html.escape(', '.join(files) or '-')}</td></tr>"
        for module, files in summary["discoveredTests"].items()
    )
    schema_inventory = summary["schemaInventory"]
    run = summary["run"]
    stdout = html.escape(run["stdout"].strip() or "-")
    stderr = html.escape(run["stderr"].strip() or "-")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RST Dashboard Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d0d7de; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f6f8fa; }}
    pre {{ background: #f6f8fa; border: 1px solid #d0d7de; padding: 1rem; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>RST Internal Checker Dashboard</h1>
  <p><strong>Generated:</strong> {html.escape(summary["generatedAt"])}</p>
  <p><strong>Status:</strong> {html.escape(run["status"])}</p>
  <h2>Discovered tests</h2>
  <table>
    <thead>
      <tr><th>Module</th><th>Files</th><th>Paths</th></tr>
    </thead>
    <tbody>
      {discovered_rows}
    </tbody>
  </table>
  <h2>Schemas</h2>
  <table>
    <tbody>
      <tr><th>JSON schemas</th><td>{schema_inventory["json_count"]}</td></tr>
      <tr><th>XSD schemas</th><td>{schema_inventory["xsd_count"]}</td></tr>
    </tbody>
  </table>
  <h2>Pytest output</h2>
  <h3>stdout</h3>
  <pre>{stdout}</pre>
  <h3>stderr</h3>
  <pre>{stderr}</pre>
</body>
</html>
"""


def write_report_files(
    *,
    summary: dict[str, Any],
    reports_root: Path,
    json_report: Path | None = None,
    html_report: Path | None = None,
) -> tuple[Path, Path]:
    effective_json_report = json_report or reports_root / "rst-dashboard-report.json"
    effective_html_report = html_report or reports_root / "rst-dashboard-report.html"
    effective_json_report.parent.mkdir(parents=True, exist_ok=True)
    effective_html_report.parent.mkdir(parents=True, exist_ok=True)
    effective_json_report.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    effective_html_report.write_text(render_html_report(summary), encoding="utf-8")
    return effective_json_report, effective_html_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run internal RST checks and write JSON/HTML summaries")
    parser.add_argument("--module", action="append", choices=DEFAULT_MODULES, help="Limit execution to one or more modules")
    parser.add_argument("--repo-root", type=Path, help="Repository root path")
    parser.add_argument("--tests-root", type=Path, help="Override tests root path")
    parser.add_argument("--schemas-root", type=Path, help="Override schemas root path")
    parser.add_argument("--reports-dir", type=Path, help="Override reports output directory")
    parser.add_argument("--json-report", type=Path, help="Optional JSON report file path")
    parser.add_argument("--html-report", type=Path, help="Optional HTML report file path")
    parser.add_argument("--dry-run", action="store_true", help="Prepare the layout and reports without running pytest")
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
    modules = tuple(args.module or DEFAULT_MODULES)

    ensure_layout(paths, modules)
    discovered_tests = discover_tests(tests_root=paths.tests_root, modules=modules)
    schema_summary = summarize_schemas(schemas_root=paths.schemas_root)
    test_paths = [paths.tests_root / relative_path for files in discovered_tests.values() for relative_path in files]
    run_summary = (
        {
            "status": "not-run",
            "returncode": 0,
            "command": [],
            "stdout": "Dry run: pytest execution skipped.",
            "stderr": "",
        }
        if args.dry_run
        else run_pytest(repo_root=paths.repo_root, test_files=test_paths)
    )

    summary = build_summary(
        paths=paths,
        modules=modules,
        discovered_tests=discovered_tests,
        schema_summary=schema_summary,
        run_summary=run_summary,
    )
    write_report_files(
        summary=summary,
        reports_root=paths.reports_root,
        json_report=args.json_report.resolve() if args.json_report else None,
        html_report=args.html_report.resolve() if args.html_report else None,
    )
    return int(run_summary["returncode"])
