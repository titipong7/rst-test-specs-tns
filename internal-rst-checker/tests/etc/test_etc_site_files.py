from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_index_contains_required_release_and_resource_links() -> None:
    index_file = _repo_root() / "etc" / "index.md"
    content = index_file.read_text(encoding="utf-8")

    required_tokens = (
        "RELEASE/rst-test-specs.html",
        "rst.json",
        "rdapct_config.json",
        "rdapct_config_rsp.json",
        "super.xsd",
        "RELEASE/rst-test-specs.json",
    )
    for token in required_tokens:
        assert token in content


def test_redirect_page_replaces_location_with_release_and_hash() -> None:
    redirect_file = _repo_root() / "etc" / "test-spec-redirect.html"
    content = redirect_file.read_text(encoding="utf-8")

    assert 'window.location.replace("RELEASE/rst-test-specs.html" + window.location.hash);' in content
