# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

This repository contains ICANN's Registry System Testing (RST) v2.0 test specifications. It has two main components:

1. **Spec Builder** (Perl/Docker) — Compiles YAML/Markdown sources in `inc/` into publishable YAML, JSON, and HTML via `docker compose run spec`. Requires Docker. Linting runs via `docker compose run lint`.
2. **Python Compliance Test Suite** (`rst-compliance-suite`) — A pytest-based scaffold in `src/rst_compliance/` with tests in `tests/`. No external services or databases required; all tests use mocks/fixtures.

### Running Python tests

```bash
pip install -e .
pytest          # runs 41 tests from tests/
```

The internal dashboard can also be run:

```bash
python3 internal-rst-checker/rst_dashboard.py
```

### Docker-based spec build and lint

The spec build and lint require Docker:

```bash
docker compose run spec   # full build (YAML, JSON, HTML)
docker compose run lint   # lint only
docker compose run pages  # build GitHub Pages output
```

**Cloud Agent caveat:** The Docker build (`docker compose build`) downloads Alpine packages and Perl/Go dependencies from the internet. If egress is restricted, the Docker image cannot be built. The Python test suite is fully functional without Docker.

### No Python-specific linter

There is no Python linter (ruff, flake8, mypy, etc.) configured in this repository. The only lint target is the Perl-based YAML spec linter run inside Docker.

### Environment notes

- Python ≥3.10 is required (3.12 available in the VM).
- `pytest` and other tools install to `~/.local/bin` — ensure this is on `PATH`.
- The `.env` file at the repo root sets `ZONEMASTER_VERSION` and `ZONEMASTER_ENGINE_VERSION`, used by the Makefile and Docker Compose.
