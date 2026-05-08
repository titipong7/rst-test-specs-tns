from __future__ import annotations

import json
from pathlib import Path

from rst_compliance.rst_dashboard import (
    DashboardPaths,
    build_summary,
    discover_tests,
    ensure_layout,
    main,
    summarize_schemas,
)


def _paths(project_root: Path, repo_root: Path) -> DashboardPaths:
    return DashboardPaths(
        repo_root=repo_root,
        project_root=project_root,
        tests_root=project_root / "tests",
        schemas_root=project_root / "schemas",
        reports_root=project_root / "reports",
    )


def test_ensure_layout_creates_expected_directories(tmp_path: Path) -> None:
    paths = _paths(tmp_path / "internal-rst-checker", tmp_path)

    ensure_layout(paths)

    assert (paths.tests_root / "epp").is_dir()
    assert (paths.tests_root / "rdap").is_dir()
    assert (paths.tests_root / "dns").is_dir()
    assert (paths.schemas_root / "json").is_dir()
    assert (paths.schemas_root / "xml").is_dir()
    assert paths.reports_root.is_dir()


def test_discover_tests_groups_files_by_module(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    (tests_root / "epp").mkdir(parents=True)
    (tests_root / "dns").mkdir(parents=True)
    (tests_root / "epp" / "test_alpha.py").write_text("", encoding="utf-8")
    (tests_root / "dns" / "test_beta.py").write_text("", encoding="utf-8")

    discovered = discover_tests(tests_root=tests_root)

    assert discovered["epp"] == ["epp/test_alpha.py"]
    assert discovered["dns"] == ["dns/test_beta.py"]
    assert discovered["rdap"] == []


def test_summarize_schemas_counts_json_and_xsd_files(tmp_path: Path) -> None:
    schemas_root = tmp_path / "schemas"
    (schemas_root / "json").mkdir(parents=True)
    (schemas_root / "xml").mkdir(parents=True)
    (schemas_root / "json" / "testCaseLog.schema.json").write_text("{}", encoding="utf-8")
    (schemas_root / "xml" / "epp-response.xsd").write_text("<schema/>", encoding="utf-8")

    summary = summarize_schemas(schemas_root=schemas_root)

    assert summary["json_count"] == 1
    assert summary["xsd_count"] == 1


def test_build_summary_counts_discovered_files(tmp_path: Path) -> None:
    paths = _paths(tmp_path / "internal-rst-checker", tmp_path)
    summary = build_summary(
        paths=paths,
        modules=("epp", "rdap", "dns"),
        discovered_tests={"epp": ["epp/test_alpha.py"], "rdap": [], "dns": ["dns/test_beta.py"]},
        schema_summary={"json_count": 1, "xsd_count": 2, "json_files": ["json/a.json"], "xsd_files": ["xml/a.xsd"]},
        run_summary={"status": "passed", "returncode": 0, "command": ["pytest"], "stdout": ".", "stderr": ""},
    )

    assert summary["testFileCount"] == 2
    assert summary["run"]["status"] == "passed"


def test_dashboard_main_dry_run_writes_reports(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    project_root = repo_root / "internal-rst-checker"
    project_root.mkdir(parents=True)

    exit_code = main(["--repo-root", str(repo_root), "--dry-run"], project_root=project_root)

    assert exit_code == 0
    json_report = project_root / "reports" / "rst-dashboard-report.json"
    html_report = project_root / "reports" / "rst-dashboard-report.html"
    assert json_report.is_file()
    assert html_report.is_file()

    report = json.loads(json_report.read_text(encoding="utf-8"))
    assert report["run"]["status"] == "not-run"
