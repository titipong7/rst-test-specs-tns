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
    summarize_epp_suite_coverage,
    summarize_etc_requirement_coverage,
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


def test_map_spec_criteria_reads_pending_suite_prefixes(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    tests_root.mkdir(parents=True)
    (tests_root / "test_pending_sample.py").write_text(
        "def test_pending_suite_cases():\n"
        "    '''covers idn-01, minimumRPMs-02, srsgw-13, integration-05'''\n"
        "    pass\n",
        encoding="utf-8",
    )

    mapping = map_spec_criteria(tests_root=tests_root)

    assert mapping[0]["criteriaIds"] == ["idn-01", "integration-05", "minimumrpms-02", "srsgw-13"]


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
        etc_requirement_coverage={"requirements": [], "summary": {"covered": 0, "partial": 0, "missing": 2}},
        epp_suite_coverage={"matrix": [], "summary": {"covered": 0, "partial": 0, "missing": 27}},
        run_summary={"status": "passed", "returncode": 0, "command": ["pytest"], "stdout": ".", "stderr": ""},
        case_results=[{"testCase": "tests::test_alpha", "status": "pass", "reason": "-", "durationSeconds": 0.1, "details": None}],
        fips_summary={"status": "pass", "standard": "FIPS 140-3", "reason": "ok", "details": {}},
        epp01_connectivity={"mode": "not-run", "status": "not-run"},
    )

    assert summary["testFileCount"] == 2
    assert summary["run"]["status"] == "passed"
    assert summary["fipsCheck"]["standard"] == "FIPS 140-3"
    assert "etcRequirementCoverage" in summary
    assert "eppSuiteCoverage" in summary
    assert summary["epp01Connectivity"]["mode"] == "not-run"


def test_summarize_etc_requirement_coverage_reports_covered_and_partial() -> None:
    coverage = summarize_etc_requirement_coverage(
        spec_mapping=[
            {
                "testName": "test_index_contains_required_release_and_resource_links",
                "file": "etc/test_etc_site_files.py",
                "module": "etc",
                "rstSpecVersion": "ICANN RST v2026.04",
                "criteriaIds": [],
            },
            {
                "testName": "test_redirect_page_replaces_location_with_release_and_hash",
                "file": "etc/test_etc_site_files.py",
                "module": "etc",
                "rstSpecVersion": "ICANN RST v2026.04",
                "criteriaIds": [],
            },
        ],
        case_results=[
            {"testCase": "tests.etc.test_etc_site_files::test_index_contains_required_release_and_resource_links", "status": "pass"},
            {"testCase": "tests.etc.test_etc_site_files::test_redirect_page_replaces_location_with_release_and_hash", "status": "fail"},
        ],
    )
    statuses = {item["id"]: item["status"] for item in coverage["requirements"]}
    assert statuses["etc-index-links"] == "covered"
    assert statuses["etc-redirect-hash"] == "partial"


def test_summarize_epp_suite_coverage_reports_covered_partial_and_missing() -> None:
    coverage = summarize_epp_suite_coverage(
        spec_mapping=[
            {
                "testName": "test_epp_service_connectivity_smoke_epp_01",
                "file": "epp/test_epp_standard_suite_smoke.py",
                "module": "epp",
                "rstSpecVersion": "ICANN RST v2026.04",
                "criteriaIds": ["epp-01"],
            },
            {
                "testName": "test_epp_domain_update_smoke_epp_16",
                "file": "epp/test_epp_standard_suite_smoke.py",
                "module": "epp",
                "rstSpecVersion": "ICANN RST v2026.04",
                "criteriaIds": ["epp-16"],
            },
        ],
        case_results=[
            {"testCase": "internal-rst-checker.tests.epp::test_epp_service_connectivity_smoke_epp_01", "status": "pass"},
            {"testCase": "internal-rst-checker.tests.epp::test_epp_domain_update_smoke_epp_16", "status": "fail"},
        ],
    )
    matrix = {item["caseId"]: item["status"] for item in coverage["matrix"]}
    assert matrix["epp-01"] == "covered"
    assert matrix["epp-16"] == "partial"
    assert matrix["epp-05"] == "missing"


def test_dashboard_main_dry_run_writes_reports(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    project_root = repo_root / "internal-rst-checker"
    tests_root = project_root / "tests"
    schemas_root = repo_root / "schemas"
    tests_root.mkdir(parents=True)
    schemas_root.mkdir(parents=True)
    (tests_root / "test_one.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
    project_root.mkdir(parents=True, exist_ok=True)

    exit_code = main(["--repo-root", str(repo_root), "--dry-run"], project_root=project_root)

    assert exit_code == 0
    json_report = project_root / "reports" / "report.json"
    html_report = project_root / "reports" / "report.html"
    assert json_report.is_file()
    assert html_report.is_file()

    report = json.loads(json_report.read_text(encoding="utf-8"))
    assert report["run"]["status"] == "not-run"
    assert report["epp01Connectivity"]["mode"] == "not-run"
