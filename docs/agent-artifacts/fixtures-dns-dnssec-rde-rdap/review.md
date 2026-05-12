# Review — Non-EPP Fixtures Re-aligned to Flat EPP Layout

> Role: **Reviewer**. Applies `.cursor/rules/review-severity-gate.mdc`
> to the Builder + Tester outputs and decides on the merge gate.

## 1. Scope under review

- Branch: `feat/non-epp-fixtures-flat-layout`
- Commits: `cbe7c1f`…`b0d58b9` (8 commits, listed in
  [`build.md`](./build.md) §2).
- Plan: [`plan.md`](./plan.md) (final version, supersedes the PR #23
  plan).
- Test evidence: [`test.md`](./test.md).

## 2. Findings (severity table)

| #  | Finding                                                                                  | Severity | Evidence                                                                                                                                                | Required action                                |
| -- | ---------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| 1  | All migrated guard tests pass (pyt cmds in test.md §2.1–§2.3).                            | n/a      | `pytest internal-rst-checker/tests -q` → `144 passed, 14 skipped`.                                                                                       | None — meets AC1..AC5, AC8.                    |
| 2  | Module-level Python suite (`tests/`) stays green.                                        | n/a      | `pytest tests -q` → `65 passed`.                                                                                                                         | None — meets AC6.                              |
| 3  | `make quality-gate` requires Perl modules (`Data::Mirror`, `ICANN::RST::Spec`) for the `includes` / `lint` sub-targets. Local environment doesn't ship them. | low      | `make quality-gate` fails at `includes` step on this workstation; same failure pattern reproduces on `main` without the migration. | Document the locally-skipped sub-targets in the PR description; CI handles them via apt installs (`.github/workflows/**` untouched, AC9). |
| 4  | Combined `pytest internal-rst-checker/tests tests` raises 3 collection errors for duplicate test module names. | low      | Pre-existing repository condition; reproduces on a clean checkout of `main`. The two roots are run separately in CI.                                  | None for this PR. Track as backlog for a separate hygiene PR (move shared `tests/test_dnssec_zone_health.py` and friends under a unique namespace). |
| 5  | DNSSEC-Ops is **still** on the per-case sub-folder layout while the other 7 suites are flat. | low      | `internal-rst-checker/fixtures/dnssec-ops/{91,92,93}-…/`; `internal-rst-checker/fixtures/README.md` explicitly flags it. Plan §1 lists it as a non-goal. | None for this PR. Track as the next work package. |
| 6  | RDE PGP signature placeholder rename `*.sig.example` → `*.asc`.                          | low      | Spec talks about ASCII-armoured PGP (`.asc` is the GnuPG convention). Renamed during migration (`f978964`).                                              | None — improvement, README documents the convention. |
| 7  | Top-level `internal-rst-checker/fixtures/README.md` accurately captures the flat layout and the DNSSEC-Ops divergence. | n/a      | Manual diff against the on-disk layout.                                                                                                                  | None — meets AC4.                              |
| 8  | Scope audit: only fixture / guard-test / docs paths are touched.                         | n/a      | `git diff main…HEAD --stat` (see test.md §3). `inc/**`, `src/rst_compliance/**`, `Makefile`, `.github/workflows/**`, `rst-test-specs.*` unmodified.       | None — meets AC9.                              |

## 3. Merge-gate decision

- **Blockers:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 4 (#3, #4, #5, #6 — all explained and either intentional or pre-existing)

→ **Merge gate cleared** (`.cursor/rules/review-severity-gate.mdc`
requires only `blocker == 0 && high == 0`).

## 4. PR description anchor

When opening the PR, copy the following summary:

> Re-aligns the 7 non-EPP suites (DNS, DNSSEC, RDE, RDAP, SRSGW, IDN,
> Integration) to the flat EPP fixture layout
> (`<nn>-<slug>-{success,failure}.<ext>` directly under the suite
> folder). Rewrites the per-suite guard tests to a glob-based
> `ACTIVE_CASES` check matching the EPP template, refreshes per-suite
> READMEs + the top-level fixtures README, and adds a layout note to
> `docs/epp-spec-to-test-mapping.md`. DNSSEC-Ops stays on its current
> per-case sub-folder layout (called out explicitly in
> `fixtures/README.md`).
>
> ### Test plan
> - `pytest -q internal-rst-checker/tests` → 144 passed, 14 documented skips
> - `pytest -q tests` → 65 passed
> - `make quality-gate-python` (Python sub-target) → green
> - `make lint` / `make includes` exercised in CI only (Perl deps).

## 5. Hand-off

Reviewer signs off — Builder may push the branch and open the PR
against `main`.
