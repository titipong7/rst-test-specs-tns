from __future__ import annotations

from rst_compliance.fips_check import check_hsm_fips_140_3_mode


def test_check_hsm_fips_140_3_mode_passes_when_probe_reports_fips_enabled() -> None:
    result = check_hsm_fips_140_3_mode(probe=lambda: {"provider": "sim", "fips_mode": True})

    assert result["status"] == "pass"
    assert result["standard"] == "FIPS 140-3"


def test_check_hsm_fips_140_3_mode_fails_when_probe_reports_fips_disabled() -> None:
    result = check_hsm_fips_140_3_mode(probe=lambda: {"provider": "sim", "fips_mode": False})

    assert result["status"] == "fail"
    assert "not operating" in result["reason"]
