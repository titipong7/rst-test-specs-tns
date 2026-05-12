# Build — Fixtures for DNS / DNSSEC / DNSSEC-Ops / RDE / RDAP / SRSGW / IDN / Integration

> Role: **Builder**. Implementing the approved Plan
> (`docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/plan.md`).
>
> Plan answers from Human:
>
> - Q1 (case inventory): _accept as-is, proceed_.
> - Q2 (layout / `*.success.*` / `*.failure.*`): _ok_.
> - Q3 (single guard test vs. per-suite): **per-suite guard tests**, mirroring
>   `internal-rst-checker/tests/epp/test_epp_th_fixtures_present.py`.
> - Q4 (PR strategy): _single follow-up PR_, but Builder still groups commits
>   per suite for review.

## Adjustment to plan

§3.3 of the plan now reads:

- One guard test per suite under
  `internal-rst-checker/tests/<suite>/test_<suite>_fixtures_present.py`
  (suite folder names use Python-friendly underscores: `dnssec_ops`).
- Each test file ships its own per-case manifest (no shared module).

All other sections of the plan stand unchanged.

## Workflow

1. Build each suite top-down: fixtures → `<suite>.env.example` → README → guard test.
2. After every suite, run the new guard test plus the full
   `internal-rst-checker/tests/` collection to confirm zero regression.
3. Append the cross-link row in `docs/epp-spec-to-test-mapping.md` only after
   all suites pass locally.
4. Commit per suite, push, open a single follow-up PR.

## Progress log

(filled as work proceeds)
