from __future__ import annotations

import json
from pathlib import Path

import pytest

from rst_compliance.rst_dashboard import (
    CASE_ID_PATTERN,
    CASE_ID_PATTERNS,
    DEFAULT_SUITES,
    DNSSEC_OPS_CASE_ID_PATTERN,
    DashboardPaths,
    _extract_case_ids,
    build_summary,
    compute_error_code_coverage,
    discover_tests,
    ensure_layout,
    load_active_case_ids,
    load_case_maturity,
    load_error_codes,
    main,
    map_spec_criteria,
    parse_junit_report,
    render_dashboard_html,
    render_html_report,
    render_terminal_table,
    rollup_maturity,
    scan_fixture_inventory,
    summarize_all_error_code_coverage,
    summarize_all_maturity,
    summarize_all_suite_coverage,
    summarize_epp_suite_coverage,
    summarize_error_code_coverage,
    summarize_etc_requirement_coverage,
    summarize_fixture_inventory,
    summarize_maturity_rollup,
    summarize_schemas,
    summarize_suite_coverage,
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
        "    '''covers idn-01, srsgw-13, integration-05'''\n"
        "    pass\n",
        encoding="utf-8",
    )

    mapping = map_spec_criteria(tests_root=tests_root)

    assert mapping[0]["criteriaIds"] == ["idn-01", "integration-05", "srsgw-13"]


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


# --------------------------------------------------------------------------- #
# F1 — generalised case_id regex                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "case_id",
    [
        "dns-zz-consistency",
        "dnssec-91",
        "srsgw-15",
        "integration-03",
        "idn-02",
        "rde-04",
        "rdap-91",
        "epp-27",
    ],
)
def test_case_id_pattern_matches_every_required_suite_form(case_id: str) -> None:
    """User-spec acceptance set: CASE_ID_PATTERN matches every required form."""
    assert CASE_ID_PATTERN.search(case_id) is not None


@pytest.mark.parametrize(
    "case_id",
    [
        "dns-zz-idna2008-compliance",
        "dnssec-91",
        "rdap-01",
        "rde-01",
        "srsgw-01",
        "idn-01",
        "integration-01",
        "epp-14",
    ],
)
def test_extract_case_ids_recognises_every_suite_format(case_id: str) -> None:
    body = f"some text mentioning {case_id} in the middle"
    assert case_id in _extract_case_ids(body)


def test_case_id_pattern_alias_preserves_existing_epp_match() -> None:
    """Legacy callers importing CASE_ID_PATTERN keep working."""
    assert CASE_ID_PATTERN.search("covers epp-03 login") is not None
    assert CASE_ID_PATTERN in CASE_ID_PATTERNS


@pytest.mark.parametrize(
    "case_id",
    [
        "dnssecOps01-ZSKRollover",
        "dnssecOps02-KSKRollover",
        "dnssecOps03-AlgorithmRollover",
    ],
)
def test_dnssec_ops_case_id_pattern_matches_camel_case_ids(case_id: str) -> None:
    """L-3: dnssecOpsNN-* case_ids are matched by the new sibling pattern."""
    assert DNSSEC_OPS_CASE_ID_PATTERN.search(case_id) is not None
    assert case_id in _extract_case_ids(f"docstring references {case_id} here")


def test_dnssec_ops_case_id_pattern_rejects_near_misses() -> None:
    """L-3: DNSSEC_OPS-pattern is anchored and does not eat surrounding prose."""
    assert DNSSEC_OPS_CASE_ID_PATTERN.search("dnssec-ops") is None
    assert DNSSEC_OPS_CASE_ID_PATTERN.search("dnssecOps-rollover") is None
    assert DNSSEC_OPS_CASE_ID_PATTERN.search("xdnssecOps01-ZSKRollover") is None
    # Bounded on the right side; underscore is a word char so does not match.
    assert DNSSEC_OPS_CASE_ID_PATTERN.search("dnssecOps01-Z_SK") is None


def test_extract_case_ids_finds_mixed_suites_and_dnssec_ops() -> None:
    """L-3: a doc string mentioning both standard and dnssec-ops case_ids yields both."""
    text = "covers epp-03 login and dnssecOps01-ZSKRollover rollover"
    extracted = _extract_case_ids(text)
    assert "epp-03" in extracted
    assert "dnssecOps01-ZSKRollover" in extracted


def test_map_spec_criteria_finds_dns_zz_case_id(tmp_path: Path) -> None:
    tests_root = tmp_path / "tests"
    tests_root.mkdir(parents=True)
    (tests_root / "test_dns_zz.py").write_text(
        "def test_dns_zz_idna2008_compliance_check():\n"
        "    '''Exercises dns-zz-idna2008-compliance.'''\n"
        "    pass\n",
        encoding="utf-8",
    )

    mapping = map_spec_criteria(tests_root=tests_root)

    assert mapping[0]["criteriaIds"] == ["dns-zz-idna2008-compliance"]


# --------------------------------------------------------------------------- #
# F2 — per-suite coverage summariser                                          #
# --------------------------------------------------------------------------- #


def test_load_active_case_ids_strips_leading_utf8_bom(tmp_path: Path) -> None:
    """L-1: a leading BOM no longer causes the first case_id to be skipped."""
    inc_root = tmp_path / "inc"
    suite_root = inc_root / "foo"
    suite_root.mkdir(parents=True)
    (suite_root / "cases.yaml").write_bytes(
        b"\xef\xbb\xbffoo-01:\n  Implemented: true\nfoo-02:\n  Implemented: true\n"
    )

    assert load_active_case_ids("foo", inc_root) == ("foo-01", "foo-02")


def test_load_error_codes_strips_leading_utf8_bom(tmp_path: Path) -> None:
    """L-1: BOM tolerance also applies to errors.yaml."""
    inc_root = tmp_path / "inc"
    suite_root = inc_root / "foo"
    suite_root.mkdir(parents=True)
    (suite_root / "errors.yaml").write_bytes(
        b"\xef\xbb\xbfFOO_ERROR_A:\n  Severity: ERROR\nFOO_ERROR_B:\n  Severity: WARNING\n"
    )

    assert load_error_codes("foo", inc_root) == {"FOO_ERROR_A", "FOO_ERROR_B"}


def test_load_case_maturity_strips_leading_utf8_bom(tmp_path: Path) -> None:
    """L-1: maturity rollup loader is also BOM-tolerant."""
    inc_root = tmp_path / "inc"
    suite_root = inc_root / "foo"
    suite_root.mkdir(parents=True)
    (suite_root / "cases.yaml").write_bytes(
        b"\xef\xbb\xbffoo-01:\n  Maturity: GA\nfoo-02:\n  Maturity: BETA\n"
    )

    maturity = load_case_maturity("foo", repo_root=tmp_path)
    assert maturity == {"foo-01": "GA", "foo-02": "BETA"}


def test_load_active_case_ids_reads_top_level_keys(tmp_path: Path) -> None:
    inc_root = tmp_path / "inc"
    suite_root = inc_root / "foo"
    suite_root.mkdir(parents=True)
    (suite_root / "cases.yaml").write_text(
        "foo-01:\n  Implemented: true\n\nfoo-02:\n  Implemented: true\n\nfoo-03:\n  Implemented: false\n",
        encoding="utf-8",
    )

    assert load_active_case_ids("foo", inc_root) == ("foo-01", "foo-02", "foo-03")


def test_load_active_case_ids_snapshot_per_default_suite(tmp_path: Path) -> None:
    """Every default suite returns its real `inc/<suite>/cases.yaml` order."""
    repo_root = Path(__file__).resolve().parents[1]
    inc_root = repo_root / "inc"
    for suite in DEFAULT_SUITES:
        cases_yaml = inc_root / suite / "cases.yaml"
        if not cases_yaml.is_file():
            continue
        ids = load_active_case_ids(suite, inc_root)
        assert isinstance(ids, tuple)
        assert all(isinstance(item, str) and item for item in ids)


def test_summarize_suite_coverage_marks_covered_partial_missing() -> None:
    coverage = summarize_suite_coverage(
        "rdap",
        spec_mapping=[
            {"module": "rdap", "testName": "test_rdap_01", "criteriaIds": ["rdap-01"]},
            {"module": "rdap", "testName": "test_rdap_02", "criteriaIds": ["rdap-02"]},
        ],
        case_results=[
            {"testCase": "tests::test_rdap_01", "status": "pass"},
            {"testCase": "tests::test_rdap_02", "status": "fail"},
        ],
        active_case_ids=("rdap-01", "rdap-02", "rdap-03"),
    )
    matrix = {row["caseId"]: row["status"] for row in coverage["matrix"]}
    assert matrix == {"rdap-01": "covered", "rdap-02": "partial", "rdap-03": "missing"}
    assert coverage["summary"] == {"covered": 1, "partial": 1, "missing": 1}


def test_summarize_all_suite_coverage_includes_every_default_suite(tmp_path: Path) -> None:
    for suite in DEFAULT_SUITES:
        suite_dir = tmp_path / "inc" / suite
        suite_dir.mkdir(parents=True)
        (suite_dir / "cases.yaml").write_text(f"{suite}-01:\n  Implemented: true\n", encoding="utf-8")

    coverage = summarize_all_suite_coverage(
        repo_root=tmp_path,
        spec_mapping=[],
        case_results=[],
    )
    # epp uses its hard-coded EPP_CASE_IDS even when inc/epp/cases.yaml is sparse.
    assert set(coverage.keys()) >= set(DEFAULT_SUITES)


def test_summarize_epp_suite_coverage_wrapper_remains_backwards_compatible() -> None:
    coverage = summarize_epp_suite_coverage(
        spec_mapping=[],
        case_results=[],
    )
    matrix = {row["caseId"]: row["status"] for row in coverage["matrix"]}
    # epp-22 historical override preserved.
    assert matrix["epp-22"] == "partial"
    # Every numeric prefix from 01..27 is present.
    assert all(f"epp-{n:02d}" in matrix for n in range(1, 28))


# --------------------------------------------------------------------------- #
# F3 — fixture inventory                                                      #
# --------------------------------------------------------------------------- #


def test_summarize_fixture_inventory_lists_success_and_failure_paths(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    suite_root = fixtures_root / "rdap"
    suite_root.mkdir(parents=True)
    (suite_root / "01-domain-query-success.json").write_text('{"ok": true}', encoding="utf-8")
    (suite_root / "01-domain-query-failure.json").write_text('{"ok": false}', encoding="utf-8")
    (suite_root / "02-nameserver-query-success.json").write_text('{}', encoding="utf-8")
    (tmp_path / "inc" / "rdap").mkdir(parents=True)
    (tmp_path / "inc" / "rdap" / "cases.yaml").write_text("rdap-01:\n\nrdap-02:\n", encoding="utf-8")

    inventory = summarize_fixture_inventory(
        fixtures_root=fixtures_root,
        repo_root=tmp_path,
        suites=("rdap",),
    )

    by_case = {row["caseId"]: row for row in inventory["rdap"]}
    assert sorted(by_case["rdap-01"]["files"]) == [
        "01-domain-query-failure.json",
        "01-domain-query-success.json",
    ]
    assert by_case["rdap-01"]["parses"]["01-domain-query-failure.json"] is True
    assert by_case["rdap-02"]["files"] == ["02-nameserver-query-success.json"]


def test_summarize_fixture_inventory_flags_malformed_payload(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    suite_root = fixtures_root / "rdap"
    suite_root.mkdir(parents=True)
    (suite_root / "01-bad-success.json").write_text("not valid json", encoding="utf-8")
    (tmp_path / "inc" / "rdap").mkdir(parents=True)
    (tmp_path / "inc" / "rdap" / "cases.yaml").write_text("rdap-01:\n", encoding="utf-8")

    inventory = summarize_fixture_inventory(
        fixtures_root=fixtures_root,
        repo_root=tmp_path,
        suites=("rdap",),
    )
    assert inventory["rdap"][0]["parses"]["01-bad-success.json"] is False


def test_scan_fixture_inventory_returns_per_case_rows_with_parses(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    suite_root = fixtures_root / "rdap"
    suite_root.mkdir(parents=True)
    (suite_root / "01-domain-query-success.json").write_text('{"ok": true}', encoding="utf-8")
    (suite_root / "01-domain-query-failure.json").write_text("not json", encoding="utf-8")
    inc_dir = tmp_path / "inc" / "rdap"
    inc_dir.mkdir(parents=True)
    (inc_dir / "cases.yaml").write_text("rdap-01:\n", encoding="utf-8")

    rows = scan_fixture_inventory(fixtures_root, "rdap", repo_root=tmp_path)
    assert isinstance(rows, list) and rows
    by_case = {row["caseId"]: row for row in rows}
    assert by_case["rdap-01"]["parses"]["01-domain-query-success.json"] is True
    assert by_case["rdap-01"]["parses"]["01-domain-query-failure.json"] is False


def test_summarize_fixture_inventory_validates_pgp_armor(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    suite_root = fixtures_root / "rde"
    suite_root.mkdir(parents=True)
    (suite_root / "02-signature-success.asc").write_text(
        "-----BEGIN PGP SIGNATURE-----\nfake-armor\n-----END PGP SIGNATURE-----\n",
        encoding="utf-8",
    )
    (suite_root / "02-signature-failure.asc").write_text("not armored", encoding="utf-8")
    (tmp_path / "inc" / "rde").mkdir(parents=True)
    (tmp_path / "inc" / "rde" / "cases.yaml").write_text("rde-02:\n", encoding="utf-8")

    inventory = summarize_fixture_inventory(
        fixtures_root=fixtures_root,
        repo_root=tmp_path,
        suites=("rde",),
    )
    parses = inventory["rde"][0]["parses"]
    assert parses["02-signature-success.asc"] is True
    assert parses["02-signature-failure.asc"] is False


# --------------------------------------------------------------------------- #
# F4 — error-code coverage                                                    #
# --------------------------------------------------------------------------- #


def test_load_error_codes_reads_top_level_keys(tmp_path: Path) -> None:
    inc_root = tmp_path / "inc"
    err_root = inc_root / "rde"
    err_root.mkdir(parents=True)
    (err_root / "errors.yaml").write_text(
        "RDE_FOO:\n  Severity: ERROR\n\nRDE_BAR:\n  Severity: CRITICAL\n",
        encoding="utf-8",
    )
    codes = load_error_codes("rde", inc_root)
    assert isinstance(codes, set)
    assert codes == {"RDE_FOO", "RDE_BAR"}


def test_summarize_error_code_coverage_detects_codes_in_failure_fixtures(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    suite_root = fixtures_root / "rdap"
    suite_root.mkdir(parents=True)
    (suite_root / "91-tls-conformance-failure.json").write_text(
        '{"err": "RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED"}',
        encoding="utf-8",
    )

    coverage = summarize_error_code_coverage(
        suite="rdap",
        error_codes=[
            "RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED",
            "RDAP_TLS_DNS_RESOLUTION_ERROR",
        ],
        fixtures_root=fixtures_root,
    )
    assert coverage["exercised"] == ["RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED"]
    assert coverage["unexercised"] == ["RDAP_TLS_DNS_RESOLUTION_ERROR"]
    assert coverage["summary"] == {"exercised": 1, "unexercised": 1, "total": 2}


def test_compute_error_code_coverage_distinguishes_exercised_codes(tmp_path: Path) -> None:
    """Builder spec: RDE_INVALID_SIGNATURE embedded in a failure XML must be marked exercised."""
    fixture = tmp_path / "02-deposit-failure.xml"
    fixture.write_text(
        "<?xml version='1.0' encoding='utf-8'?>"
        "<rdeReport><error>RDE_INVALID_SIGNATURE</error></rdeReport>",
        encoding="utf-8",
    )

    coverage = compute_error_code_coverage(
        [fixture],
        {"RDE_INVALID_SIGNATURE", "RDE_DEPOSIT_NOT_FOUND"},
    )

    assert coverage["exercised"] == ["RDE_INVALID_SIGNATURE"]
    assert coverage["unexercised"] == ["RDE_DEPOSIT_NOT_FOUND"]
    assert coverage["summary"] == {"exercised": 1, "unexercised": 1, "total": 2}


def test_summarize_error_code_coverage_handles_empty_failure_set(tmp_path: Path) -> None:
    fixtures_root = tmp_path / "fixtures"
    (fixtures_root / "rde").mkdir(parents=True)

    coverage = summarize_error_code_coverage(
        suite="rde",
        error_codes=["RDE_FOO", "RDE_BAR"],
        fixtures_root=fixtures_root,
    )
    assert coverage["exercised"] == []
    assert set(coverage["unexercised"]) == {"RDE_FOO", "RDE_BAR"}


# --------------------------------------------------------------------------- #
# F5 — maturity rollup                                                        #
# --------------------------------------------------------------------------- #


def test_load_case_maturity_returns_per_case_levels(tmp_path: Path) -> None:
    suite_root = tmp_path / "inc" / "rde"
    suite_root.mkdir(parents=True)
    (suite_root / "cases.yaml").write_text(
        "rde-01:\n  Maturity: GAMMA\n\nrde-02:\n  Maturity: BETA\n\nrde-03:\n  Summary: no maturity\n",
        encoding="utf-8",
    )
    maturity = load_case_maturity("rde", repo_root=tmp_path)
    assert maturity == {"rde-01": "GAMMA", "rde-02": "BETA", "rde-03": "UNKNOWN"}


def test_summarize_maturity_rollup_counts_levels() -> None:
    rollup = summarize_maturity_rollup(
        suite="rde",
        case_maturity={"a": "GAMMA", "b": "GAMMA", "c": "BETA", "d": "ALPHA"},
    )
    assert rollup["GAMMA"] == 2
    assert rollup["BETA"] == 1
    assert rollup["ALPHA"] == 1
    assert rollup["total"] == 4


def test_rollup_maturity_reads_cases_yaml_directly(tmp_path: Path) -> None:
    cases_yaml = tmp_path / "cases.yaml"
    cases_yaml.write_text(
        "foo-01:\n  Maturity: GAMMA\n\n"
        "foo-02:\n  Maturity: BETA\n\n"
        "foo-03:\n  Maturity: BETA\n\n"
        "foo-04:\n  Summary: missing maturity\n",
        encoding="utf-8",
    )
    rollup = rollup_maturity(cases_yaml)
    assert rollup["GAMMA"] == 1
    assert rollup["BETA"] == 2
    assert rollup["UNKNOWN"] == 1
    assert rollup["total"] == 4


# --------------------------------------------------------------------------- #
# F6 — richer HTML renderer                                                   #
# --------------------------------------------------------------------------- #


def _minimal_summary() -> dict:
    return {
        "generatedAt": "2026-05-12T00:00:00Z",
        "rstSpecVersion": "ICANN RST v2026.04",
        "run": {"status": "passed"},
        "suiteCoverage": {
            "rdap": {
                "matrix": [
                    {"caseId": "rdap-01", "status": "covered", "tests": ["test_rdap_01"], "reason": "Mapped tests passed"}
                ],
                "summary": {"covered": 1, "partial": 0, "missing": 0},
            },
            "rde": {
                "matrix": [
                    {"caseId": "rde-04", "status": "partial", "tests": ["test_rde_04"], "reason": "Mapped test failed"},
                ],
                "summary": {"covered": 0, "partial": 1, "missing": 0},
            },
        },
        "fixtureInventory": {
            "rdap": [{"caseId": "rdap-01", "files": ["01-x.json"], "parses": {"01-x.json": True}}],
            "rde": [
                {
                    "caseId": "rde-04",
                    "files": ["04-a.xml", "04-b.xml", "04-c.xml", "04-d.xml", "04-e.xml", "04-f.xml"],
                    "parses": {f"04-{ch}.xml": True for ch in "abcdef"},
                }
            ],
        },
        "errorCodeCoverage": {
            "rdap": {
                "exercised": ["RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED"],
                "unexercised": ["RDAP_TLS_DNS_RESOLUTION_ERROR"],
                "summary": {"exercised": 1, "unexercised": 1, "total": 2},
            }
        },
        "maturitySummary": {
            "rdap": {"GAMMA": 1, "BETA": 0, "ALPHA": 0, "UNKNOWN": 0, "total": 1},
        },
        "caseResults": [
            {"testCase": "tests::test_rdap_01", "status": "pass", "reason": "-"},
        ],
    }


def test_render_dashboard_html_includes_every_section() -> None:
    html = render_dashboard_html(_minimal_summary())
    for marker in (
        "Per-suite coverage",
        "Fixture inventory",
        "Error-code coverage",
        "Maturity rollup",
        "Case results",
        "rdap-01",
        "rde-04",
        "RDAP_TLS_FORBIDDEN_PROTOCOL_SUPPORTED",
    ):
        assert marker in html, f"missing section marker {marker!r}"


def test_render_dashboard_html_is_self_contained_no_js() -> None:
    html = render_dashboard_html(_minimal_summary())
    assert "<script" not in html
    # The single allowed external link is the ICANN spec reference in the header.
    external_urls = [u for u in ("http://", "https://") if u in html]
    if external_urls:
        for line in html.splitlines():
            if "http://" in line or "https://" in line:
                assert "icann.github.io" in line


def test_render_dashboard_html_caps_long_fixture_lists() -> None:
    html = render_dashboard_html(_minimal_summary())
    # rde-04 has 6 files; we cap at 4 with a "+2 more" indicator.
    assert "+2 more" in html


def test_render_html_report_emits_every_required_section() -> None:
    """Builder spec: output must contain <section>s/headers for each report area."""
    html = render_html_report(_minimal_summary())
    for header in (
        "Per-suite coverage",
        "Fixture inventory",
        "Error-code coverage",
        "Case results",
    ):
        assert f"<h2>{header}</h2>" in html, f"missing <h2>{header}</h2>"


# --------------------------------------------------------------------------- #
# F7 — CLI flags + dashboard html wiring                                      #
# --------------------------------------------------------------------------- #


def _bootstrap_minimal_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo_root = tmp_path / "repo"
    project_root = repo_root / "internal-rst-checker"
    (project_root / "tests").mkdir(parents=True)
    (project_root / "fixtures" / "rdap").mkdir(parents=True)
    (project_root / "fixtures" / "rdap" / "01-x-success.json").write_text(
        '{"rdapConformance": ["rdap_level_0"]}',
        encoding="utf-8",
    )
    (repo_root / "schemas").mkdir(parents=True)
    (repo_root / "inc" / "rdap").mkdir(parents=True)
    (repo_root / "inc" / "rdap" / "cases.yaml").write_text("rdap-01:\n  Maturity: GAMMA\n", encoding="utf-8")
    (repo_root / "inc" / "rdap" / "errors.yaml").write_text("RDAP_FOO:\n  Severity: ERROR\n", encoding="utf-8")
    return repo_root, project_root


def test_dashboard_main_writes_dashboard_html(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)

    exit_code = main(
        ["--repo-root", str(repo_root), "--dry-run"],
        project_root=project_root,
    )
    assert exit_code == 0
    dashboard = project_root / "reports" / "dashboard.html"
    assert dashboard.is_file()
    content = dashboard.read_text(encoding="utf-8")
    assert "rdap-01" in content


def test_dashboard_main_no_dashboard_flag_skips_html(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)

    exit_code = main(
        ["--repo-root", str(repo_root), "--dry-run", "--no-dashboard"],
        project_root=project_root,
    )
    assert exit_code == 0
    assert not (project_root / "reports" / "dashboard.html").exists()
    assert (project_root / "reports" / "report.json").is_file()


def test_dashboard_main_suite_filter_limits_keys(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)
    # Add a second suite so the filter has something to drop.
    (repo_root / "inc" / "rde").mkdir(parents=True)
    (repo_root / "inc" / "rde" / "cases.yaml").write_text("rde-01:\n", encoding="utf-8")
    (repo_root / "inc" / "rde" / "errors.yaml").write_text("RDE_FOO:\n", encoding="utf-8")

    main(
        ["--repo-root", str(repo_root), "--dry-run", "--suite", "rdap"],
        project_root=project_root,
    )
    report = json.loads((project_root / "reports" / "report.json").read_text(encoding="utf-8"))
    assert set(report["suiteCoverage"].keys()) == {"rdap"}
    assert set(report["maturitySummary"].keys()) == {"rdap"}


def test_dashboard_main_skip_fixtures_empties_inventory(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)
    main(
        ["--repo-root", str(repo_root), "--dry-run", "--skip-fixtures"],
        project_root=project_root,
    )
    report = json.loads((project_root / "reports" / "report.json").read_text(encoding="utf-8"))
    assert report["fixtureInventory"] == {}


def test_dashboard_main_skip_errors_empties_error_coverage(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)
    main(
        ["--repo-root", str(repo_root), "--dry-run", "--skip-errors"],
        project_root=project_root,
    )
    report = json.loads((project_root / "reports" / "report.json").read_text(encoding="utf-8"))
    assert report["errorCodeCoverage"] == {}


def test_dashboard_main_preserves_legacy_keys_additive_only(tmp_path: Path) -> None:
    repo_root, project_root = _bootstrap_minimal_repo(tmp_path)
    main(["--repo-root", str(repo_root), "--dry-run"], project_root=project_root)
    report = json.loads((project_root / "reports" / "report.json").read_text(encoding="utf-8"))
    legacy_keys = {
        "caseResults",
        "discoveredTests",
        "epp01Connectivity",
        "eppSuiteCoverage",
        "etcRequirementCoverage",
        "fipsCheck",
        "generatedAt",
        "projectRoot",
        "repoRoot",
        "reportsRoot",
        "rstSpecVersion",
        "run",
        "schemaInventory",
        "schemasRoot",
        "specMapping",
        "testFileCount",
        "testsRoot",
    }
    assert legacy_keys.issubset(set(report.keys()))
