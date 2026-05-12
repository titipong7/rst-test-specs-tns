# Build — Non-EPP Fixtures Re-aligned to Flat EPP Layout

> Role: **Builder**. Executes the approved [`plan.md`](./plan.md) and
> hands off green diffs to the Tester.

## 1. Strategy

- Branch from `feat/non-epp-fixtures` tip (= PR #23 merge content):
  `feat/non-epp-fixtures-flat-layout`.
- Re-align suites **one commit at a time**, in plan order
  (DNS → DNSSEC → RDE → RDAP → SRSGW → IDN → Integration).
- For every suite: `git mv` per-case sub-folder files into the new
  flat names → remove empty sub-folders → rewrite the per-suite guard
  test → refresh the suite README → `pytest -q tests/<suite>` →
  commit.
- A final commit refreshes the top-level
  `internal-rst-checker/fixtures/README.md` and the layout note in
  `docs/epp-spec-to-test-mapping.md`.

This keeps every commit reviewable (one suite ≈ one commit), avoids
"big-bang" diffs, and lets pytest validate the rename chain before the
next suite starts.

## 2. Commits landed on `feat/non-epp-fixtures-flat-layout`

| # | SHA       | Summary                                                |
| - | --------- | ------------------------------------------------------ |
| 1 | `cbe7c1f` | `fixtures(dns): re-align to flat EPP-style layout`     |
| 2 | `22769fe` | `fixtures(dnssec): re-align to flat EPP-style layout`  |
| 3 | `f978964` | `fixtures(rde): re-align to flat EPP-style layout`     |
| 4 | `0323efd` | `fixtures(rdap): re-align to flat EPP-style layout`    |
| 5 | `20bb337` | `fixtures(srsgw): re-align to flat EPP-style layout`   |
| 6 | `47af21b` | `fixtures(idn): re-align to flat EPP-style layout`     |
| 7 | `1c47b27` | `fixtures(integration): re-align to flat EPP-style layout` |
| 8 | `b0d58b9` | `docs(fixtures): refresh top-level READMEs for flat layout` |
| 9 | _follow-up_ | `fixtures(dnssec-ops): re-align to flat EPP-style layout` |

Plus this build/test/review artifact triplet under
`docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/`.

### 2.1 DNSSEC-Ops follow-up (12 May 2026)

DNSSEC-Ops was originally tagged as out-of-scope and left on
per-case sub-folders. The follow-up commit re-aligns it to the same
flat layout as the other seven suites:

| Old path                                                 | New path                                  |
| -------------------------------------------------------- | ----------------------------------------- |
| `dnssec-ops/01-zsk-rollover/config.success.json`         | `dnssec-ops/01-zsk-rollover-success.json` |
| `dnssec-ops/01-zsk-rollover/config.failure.json`         | `dnssec-ops/01-zsk-rollover-failure.json` |
| `dnssec-ops/01-zsk-rollover/tsig.env.example`            | `dnssec-ops/01-zsk-rollover-tsig.env.example` |
| `dnssec-ops/02-ksk-rollover/config.{success,failure}.json` | `dnssec-ops/02-ksk-rollover-{success,failure}.json` |
| `dnssec-ops/03-algorithm-rollover/config.{success,failure}.json` | `dnssec-ops/03-algorithm-rollover-{success,failure}.json` |

The DNSSEC-Ops guard test (`tests/dnssec_ops/test_dnssec_ops_fixtures_present.py`)
is rewritten to the same flat-glob `ACTIVE_CASES` pattern used by every
other suite (`("01", "02", "03")`).

## 3. Naming decisions (deviations from §3.3)

The plan §3.3 lists `02-host-create-gateway.xml` etc.; the
`git mv` automation initially produced `02-host-create-create.xml`
because the slug-stripping logic kept the original verb. A second
pass renamed every gateway-frame file to the planned
`-gateway` token. The final SRSGW filenames match the plan exactly:

```
02-host-create-gateway.xml         05-domain-renew-gateway.xml
03-contact-create-gateway.xml      08-domain-delete-gateway.xml
04-domain-create-gateway.xml       09-host-update-gateway.xml
                                   10-host-delete-gateway.xml
                                   11-contact-update-gateway.xml
                                   12-contact-delete-gateway.xml
```

Two suites required minor slug shortening, kept transparent in the
suite README:

- Integration `04-glue-policy-host-objects/*` → `04-glue-host-objects-*`
- Integration `05-glue-policy-host-attributes/*` → `05-glue-host-attributes-*`

(The `-policy-` token was dropped to keep filenames under the 64-char
"easy-scan" threshold used by the EPP template; the README is the
single source of truth for the human-readable case description.)

## 4. Guard-test rewrites

Every per-suite guard test now uses the **flat-glob EPP pattern**:

```python
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "<suite>"

ACTIVE_CASES: tuple[str, ...] = (...)

def _all_fixture_files() -> list[Path]:
    return sorted(p for p in FIXTURE_DIR.iterdir()
                  if p.is_file() and p.name != "README.md")

@pytest.mark.parametrize("case_nn", ACTIVE_CASES)
def test_every_active_<suite>_case_has_at_least_one_fixture(case_nn):
    matches = sorted(FIXTURE_DIR.glob(f"{case_nn}-*"))
    assert matches, ...
```

The previous PR #23 shape (a manually-curated `ACTIVE_CASES` dict
listing per-file paths) is dropped because every active case now
satisfies the simpler "at least one `<nn>-*` file" invariant. JSON /
XML parse checks keep the `_files_or_placeholder` idiom to handle
suites where one of the extensions is empty (pytest's
`parametrize` rejects an empty list).

## 5. Top-level docs touched

- `internal-rst-checker/fixtures/README.md` — table rebuilt; explicit
  call-out that DNSSEC-Ops still ships per-case sub-folders.
- `docs/epp-spec-to-test-mapping.md` — appended layout note under the
  "Non-EPP Suite Fixture Pointers" section.

No other files modified (audit in `test.md` §3).

## 6. Hand-off to Tester

- Branch tip: `feat/non-epp-fixtures-flat-layout`
- Latest commit: `b0d58b9 docs(fixtures): refresh top-level READMEs for flat layout`
- Outstanding work: Tester verifies AC1..AC9 against the plan; AC10
  handled in the Reviewer phase.
