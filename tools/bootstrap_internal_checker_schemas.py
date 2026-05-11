#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def _copy_by_extension(*, source_dir: Path, destination_dir: Path, extension: str) -> int:
    destination_dir.mkdir(parents=True, exist_ok=True)
    for existing in destination_dir.glob(f"*{extension}"):
        existing.unlink()

    copied = 0
    if not source_dir.exists():
        return copied

    for src in sorted(source_dir.glob(f"*{extension}")):
        shutil.copy2(src, destination_dir / src.name)
        copied += 1
    return copied


def bootstrap_internal_checker_schemas(*, repo_root: Path) -> dict[str, int]:
    source_base = repo_root / "schemas" / "rst-api-spec" / "v2026.4"
    target_base = repo_root / "internal-rst-checker" / "schemas"

    json_count = _copy_by_extension(
        source_dir=source_base / "json",
        destination_dir=target_base / "json",
        extension=".json",
    )
    xsd_count = _copy_by_extension(
        source_dir=source_base / "xml",
        destination_dir=target_base / "xml",
        extension=".xsd",
    )
    return {"json": json_count, "xsd": xsd_count}


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap internal-rst-checker schemas from official rst-api-spec folders")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1], help="Path to repository root")
    args = parser.parse_args()

    result = bootstrap_internal_checker_schemas(repo_root=args.repo_root.resolve())
    print(
        "Bootstrapped internal checker schemas "
        f"(json={result['json']}, xsd={result['xsd']}) "
        f"from {args.repo_root / 'schemas' / 'rst-api-spec' / 'v2026.4'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
