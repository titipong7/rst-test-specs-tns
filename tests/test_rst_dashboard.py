from __future__ import annotations

import json
from pathlib import Path

from rst_compliance.rst_dashboard import (
    DashboardPaths,
    build_summary,
    discover_tests,
    ensure_layout,
    main,
    map_spec_criteria,
    parse_junit_report,
    render_terminal_table,
    summarize_schemas,
)


def _paths(project_root: Path, repo_root: Path) -> DashboardPaths:
    return DashboardPaths(
        repo_root=repo_root,
        project_root=project_root,
        tests_root=repo_root / "tests",
        schemas_root=repo_root / "schemas",
        reports_root=project_root / "reports",
    )


def test_ensure_layout_creates_reports_directory(tmp_path: Path) -> None:
    paths = _paths(tmp_path / "internal-rst-checker", tmp_path)

    ensure_layout(paths)

    assert paths.reports_root.is_dir()


def test_discover_tests_groups_files_by_module(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    (tests_root / "epp").mkdir(parents=True)
    (tests_root / "test_alpha.py").write_text("", encoding="utf-8")
    (tests_root / "epp" / "test_beta.py").write_text("", encoding="utf-8")

    discovered = discover_tests(tests_root=tests_root)

    assert discovered["tests"] == ["test_alpha.py"]
    assert discovered["epp"] == ["epp/test_beta.py"]


def test_map_spec_criteria_reads_test_functions(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    tests_root.mkdir(parents=True)
    (tests_root / "test_rdap_sample.py").write_text(
        "def test_rdap_01_validates_payload():\n"
        "    '''covers rdap-01'''\n"
        "    pass\n",
        encoding="utf-8",
    )

    mapping = map_spec_criteria(tests_root=tests_root)

    assert mapping[0]["rstSpecVersion"] == "ICANN RST v2026.04"
    assert mapping[0]["criteriaIds"] == ["rdap-01"]


def test_summarize_schemas_counts_json_and_xsd_files(tmp_path: Path) -> None:
    schemas_root = tmp_path / "schemas"
    (schemas_root / "json").mkdir(parents=True)
    (schemas_root / "xml").mkdir(parents=True)
    (schemas_root / "json" / "testCaseLog.schema.json").write_text("{}", encoding="utf-8")
    (schemas_root / "xml" / "epp-response.xsd").write_text("<schema/>", encoding="utf-8")

    summary = summarize_schemas(schemas_root=schemas_root)

    assert summary["json_count"] == 1
    assert summary["xsd_count"] == 1


def test_parse_junit_report_and_render_terminal_table(tmp_path: Path) -> None:
    report = tmp_path / "report.xml"
    report.write_text(
        "<?xml version='1.0' encoding='utf-8'?>\n"
        "<testsuite tests='2' failures='1'>\n"
        "  <testcase classname='tests.test_x' name='test_ok' time='0.01'/>\n"
        "  <testcase classname='tests.test_x' name='test_fail' time='0.02'>\n"
        "    <failure message='assert 1 == 2'>Traceback</failure>\n"
        "  </testcase>\n"
        "</testsuite>\n",
        encoding="utf-8",
    )

    cases = parse_junit_report(report_file=report)
    table = render_terminal_table(cases)

    assert len(cases) == 2
    assert cases[1]["status"] == "fail"
    assert "test_fail" in table


def test_build_summary_counts_discovered_files(tmp_path: Path) -> None:
    paths = _paths(tmp_path / "internal-rst-checker", tmp_path)
    summary = build_summary(
        paths=paths,
        discovered_tests={"tests": ["test_alpha.py", "test_beta.py"]},
        spec_mapping=[{"testName": "test_alpha", "criteriaIds": []}],
        schema_summary={"json_count": 1, "xsd_count": 2, "json_files": ["json/a.json"], "xsd_files": ["xml/a.xsd"]},
        run_summary={"status": "passed", "returncode": 0, "command": ["pytest"], "stdout": ".", "stderr": ""},
        case_results=[{"testCase": "tests::test_alpha", "status": "pass", "reason": "-", "durationSeconds": 0.1, "details": None}],
        fips_summary={"status": "pass", "standard": "FIPS 140-3", "reason": "ok", "details": {}},
    )

    assert summary["testFileCount"] == 2
    assert summary["run"]["status"] == "passed"
    assert summary["fipsCheck"]["standard"] == "FIPS 140-3"


def test_dashboard_main_dry_run_writes_reports(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    project_root = repo_root / "internal-rst-checker"
    tests_root = repo_root / "tests"
    schemas_root = repo_root / "schemas"
    tests_root.mkdir(parents=True)
    schemas_root.mkdir(parents=True)
    (tests_root / "test_one.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
    project_root.mkdir(parents=True)

    exit_code = main(["--repo-root", str(repo_root), "--dry-run"], project_root=project_root)

    assert exit_code == 0
    json_report = project_root / "reports" / "report.json"
    html_report = project_root / "reports" / "report.html"
    assert json_report.is_file()
    assert html_report.is_file()

    report = json.loads(json_report.read_text(encoding="utf-8"))
    assert report["run"]["status"] == "not-run"
