# Plan — Fixtures for DNS / DNSSEC / DNSSEC-Ops / RDE / RDAP / SRSGW / IDN / Integration

> Role: **Planner** (read-only). No code, no fixtures, no tests created in this
> phase. Awaiting Human approval before handing off to Builder.
>
> Spec reference: ICANN RST `v2026.04`
> (`https://icann.github.io/rst-test-specs/v2026.04/rst-test-specs.html`).

> **Update (12 May 2026)** — Layout re-alignment is now applied to **all
> 8 non-EPP suites including DNSSEC-Ops**. The initial revision of
> PR #24 ("re-align to flat EPP layout") kept DNSSEC-Ops on its
> per-case sub-folder layout as a non-goal. A follow-up commit on the
> same branch re-aligns DNSSEC-Ops to the flat
> `<nn>-<slug>-{success,failure}.<ext>` shape used by every other
> suite. The case inventory in §2 is unchanged; the directory layout
> in §3.1 is now interpreted as "flat names per suite, no
> sub-folders" everywhere.

## 1. Goal restated

Fill the fixture coverage gap left by the EPP work. Every active test case in
the suites below must ship at least one fixture (happy path + negative path
where applicable), shaped after the proven layout under
`internal-rst-checker/fixtures/epp/th/` and guarded by a smoke test
analogous to `internal-rst-checker/tests/epp/test_epp_th_fixtures_present.py`.

## 2. Scope

### In scope (case inventory pulled from `inc/<suite>/cases.yaml`)

| Suite          | Source                          | Cases                                                                                                                                                                                                              | # |
| -------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | - |
| `dns`          | `inc/dns/cases.yaml`            | `dns-zz-idna2008-compliance`, `dns-zz-consistency`                                                                                                                                                                 | 2 |
| `dnssec`       | `inc/dnssec/cases.yaml`         | `dnssec-91`, `dnssec-92`, `dnssec-93`                                                                                                                                                                              | 3 |
| `dnssec-ops`   | `inc/dnssec-ops/cases.yaml`     | `dnssecOps01-ZSKRollover`, `dnssecOps02-KSKRollover`, `dnssecOps03-AlgorithmRollover`                                                                                                                              | 3 |
| `rde`          | `inc/rde/cases.yaml`            | `rde-01` … `rde-14`                                                                                                                                                                                                | 14|
| `rdap`         | `inc/rdap/cases.yaml`           | `rdap-01` … `rdap-10`, `rdap-91`, `rdap-92`                                                                                                                                                                        | 12|
| `srsgw`        | `inc/srsgw/cases.yaml`          | `srsgw-01..06`, `srsgw-08..15` (no `srsgw-07` — merged into `srsgw-06` per spec comment)                                                                                                                            | 14|
| `idn`          | `inc/idn/cases.yaml`            | `idn-01`, `idn-02`                                                                                                                                                                                                 | 2 |
| `integration`  | `inc/integration/cases.yaml`    | `integration-01` … `integration-05`                                                                                                                                                                                | 5 |
| **Total**      |                                 |                                                                                                                                                                                                                    | **55** |

### Non-goals (do not touch in this work item)

- `rst-test-specs.*`, `inc/**/cases.yaml`, `inc/**/errors.yaml`,
  `inc/**/inputs.yaml` — the spec is read-only ground truth.
- The `epp/th` fixture set already shipped in PR #22 / `feat/epp-th-fixtures-complete`.
- `Makefile`, CI workflow, dashboard report logic, `epp_client.py`, or any
  rule helper. Pure data + one new presence-guard test only.
- Real credentials, signed PGP keys, real cert/key bytes, or real registry
  contents. Only `*.env.example` placeholders + obviously synthetic data.

## 3. Output shape (proposal pending approval)

### 3.1 Directory layout

Mirror the per-suite, per-case style already used by `epp/th`. Each suite
gets its own folder under `internal-rst-checker/fixtures/`:

```
internal-rst-checker/fixtures/
├── dns/
│   ├── README.md
│   ├── dns.env.example
│   ├── idna2008-compliance/
│   │   ├── nameservers.success.json
│   │   ├── nameservers.failure.json
│   │   └── apex-rrsets.zone
│   └── consistency/
│       ├── nameservers.success.json
│       ├── nameservers.failure.json
│       └── query-matrix.json
├── dnssec/
│   ├── README.md
│   ├── dnssec.env.example
│   ├── 91-signing-algorithm/{ds-records.success.json,ds-records.failure.json}
│   ├── 92-ds-digest-algorithm/{ds-records.success.json,ds-records.failure.json}
│   └── 93-nsec3-iterations/{nsec3param.success.json,nsec3param.failure.json}
├── dnssec-ops/
│   ├── README.md
│   ├── dnssec-ops.env.example
│   ├── 01-zsk-rollover/{config.success.json,config.failure.json,tsig.env.example}
│   ├── 02-ksk-rollover/{config.success.json,config.failure.json}
│   └── 03-algorithm-rollover/{config.success.json,config.failure.json}
├── rde/
│   ├── README.md
│   ├── rde.env.example
│   ├── 01-deposit-filename/{filename.success.txt,filename.failure.txt}
│   ├── 02-signature/{signature.success.sig.example,signature.failure.sig.example}
│   ├── 03-decrypt/{deposit.success.ryde.example,deposit.failure.ryde.example}
│   ├── 04-xml-csv/{deposit.success.xml,deposit.failure.xml,deposit.success.csv,deposit.failure.csv}
│   ├── 05-object-types/{header.success.xml,header.failure.xml}
│   ├── 06-object-counts/{header.success.xml,header.failure.xml}
│   ├── 07-domain/{domain.success.xml,domain.failure.xml}
│   ├── 08-host/{host.success.xml,host.failure.xml}
│   ├── 09-contact/{contact.success.xml,contact.failure.xml}
│   ├── 10-registrar/{registrar.success.xml,registrar.failure.xml}
│   ├── 11-idn-table/{idn.success.xml,idn.failure.xml}
│   ├── 12-nndn/{nndn.success.xml,nndn.failure.xml}
│   ├── 13-epp-params/{epp-params.success.xml,epp-params.failure.xml}
│   └── 14-policy/{policy.success.xml,policy.failure.xml}
├── rdap/
│   ├── README.md
│   ├── rdap.env.example
│   ├── 01-domain-query/{request.http,response.success.json,response.failure.json}
│   ├── 02-nameserver-query/{request.http,response.success.json,response.failure.json}
│   ├── 03-entity-query/{request.http,response.success.json,response.failure.json}
│   ├── 04-help-query/{request.http,response.success.json,response.failure.json}
│   ├── 05-domain-head/{request.http,response.success.txt,response.failure.txt}
│   ├── 06-nameserver-head/{request.http,response.success.txt,response.failure.txt}
│   ├── 07-entity-head/{request.http,response.success.txt,response.failure.txt}
│   ├── 08-non-existent-domain/{request.http,response.success.json,response.failure.json}
│   ├── 09-non-existent-nameserver/{request.http,response.success.json,response.failure.json}
│   ├── 10-non-existent-entity/{request.http,response.success.json,response.failure.json}
│   ├── 91-tls-conformance/{probe.success.json,probe.failure.json}
│   └── 92-service-port-consistency/{probe.success.json,probe.failure.json}
├── srsgw/
│   ├── README.md
│   ├── srsgw.env.example
│   ├── 01-connectivity/{hello.xml}
│   ├── 02-host-create/{gateway-create.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 03-contact-create/{gateway-create.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 04-domain-create/{gateway-create.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 05-domain-renew/{gateway-renew.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 06-domain-transfer/{gateway-request.xml,gateway-approve.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 08-domain-delete/{gateway-delete.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 09-host-update/{gateway-update.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 10-host-delete/{gateway-delete.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 11-contact-update/{gateway-update.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 12-contact-delete/{gateway-delete.xml,primary-info.success.xml,primary-info.failure.xml}
│   ├── 13-domain-rdap/{rdap-primary.success.json,rdap-gateway.success.json,rdap-gateway.failure.json}
│   ├── 14-nameserver-rdap/{rdap-primary.success.json,rdap-gateway.success.json,rdap-gateway.failure.json}
│   └── 15-registrar-rdap/{rdap-primary.success.json,rdap-gateway.success.json,rdap-gateway.failure.json}
├── idn/
│   ├── README.md
│   ├── idn.env.example
│   ├── 01-label-validation/{create.success.xml,create.failure.xml,variant-create.failure.xml}
│   └── 02-ascii-in-idn-only-tld/{create.failure.xml}
└── integration/
    ├── README.md
    ├── integration.env.example
    ├── 01-epp-rdap/{epp-create.xml,rdap-response.success.json,rdap-response.failure.json}
    ├── 02-epp-dns/{epp-create.xml,dns-query.success.json,dns-query.failure.json}
    ├── 03-epp-rde/{epp-create.xml,rde-deposit.success.xml,rde-deposit.failure.xml,sftp.env.example}
    ├── 04-glue-policy-host-objects/{epp-create-domain.xml,epp-create-host.xml,epp-update-domain.xml,dns-query.success.json,dns-query.failure.json}
    └── 05-glue-policy-host-attributes/{epp-create-domain-1.xml,epp-create-domain-2.xml,dns-query.success.json,dns-query.failure.json}
```

Naming convention (consistent with `epp/th`):

- `<artifact>.success.<ext>` — happy path that the case must accept.
- `<artifact>.failure.<ext>` — negative path that the case must reject.
- Reuse already-tracked file types where possible: `*.xml`, `*.json`,
  `*.csv`, `*.zone`, `*.http`, `*.txt`. Anything that would normally be
  binary or contain key material gets a `.example` suffix and a clearly
  synthetic body.

### 3.2 Per-suite README

Each `README.md` will mirror the `epp/th` format:

1. Suite overview and spec link to the upstream test case.
2. Connection / runtime template referencing `<suite>.env.example`.
3. Per-case fixture table (`Spec case` / `Happy path` / `Negative path` /
   `Notes`), explicitly listing any "if applicable" skip conditions
   (`epp.hostModel`, `srsgw.registryDataModel`, `dns.gluePolicy`, etc.).
4. Placeholder conventions section (synthetic IPs / hostnames / handles).

### 3.3 Smoke test

One additional file:
`internal-rst-checker/tests/_fixtures/test_suite_fixtures_present.py`
(new package init `internal-rst-checker/tests/_fixtures/__init__.py`).

Behavior, modeled on `test_epp_th_fixtures_present.py`:

- Single source-of-truth manifest in the test module mapping
  `(suite, case_id) → required fixture filenames`.
- `test_active_case_has_at_least_one_fixture[suite-case]` — fails fast if a
  case loses every fixture file.
- `test_case_has_happy_and_negative_pair[suite-case]` — for every case where
  the spec describes both branches (i.e. all except removed-or-skip cases),
  asserts both `*.success.*` and `*.failure.*` exist.
- `test_xml_fixtures_are_well_formed[path]` — XML well-formedness check for
  every `*.xml` shipped under the new folders.
- `test_json_fixtures_are_valid[path]` — `json.loads()` for every `*.json`.
- `test_no_real_secrets_committed[path]` — hard-fail if any `*.env` file
  (without `.example`) lands under the new folders, mirroring the existing
  `.gitignore` rule.

### 3.4 Documentation cross-links (read-only or append-only)

- Append a "Fixture pointer" column to `docs/epp-spec-to-test-mapping.md`
  for each non-EPP suite (only an append, not a structural rewrite).
- Add a top-level note in `internal-rst-checker/fixtures/README.md` (create
  if missing) listing the seven new sub-folders.

No other docs touched.

## 4. Acceptance criteria

1. Every case listed in §2 has at least one fixture file matching the
   structure in §3.1.
2. Every case that has both a happy and negative branch in the spec has
   both `*.success.*` and `*.failure.*` artifacts.
3. The new presence-guard tests pass locally:
   `.venv/bin/pytest internal-rst-checker/tests/_fixtures -q`.
4. Existing test suite stays green:
   `.venv/bin/pytest internal-rst-checker/tests -q` reports the same
   pass/skip counts as before (no regression in `epp` / `dns` / `rdap` /
   `etc` packages).
5. Each new fixture folder has a `README.md` matching the `epp/th` format
   with a per-case fixture table and placeholder conventions.
6. No `*.env` (only `*.env.example`) files added; `.gitignore` already
   covers `internal-rst-checker/fixtures/**/*.env` so this only needs to
   be verified, not modified.
7. No spec files (`inc/**/*.yaml`, `rst-test-specs.*`) modified.
8. Reviewer report contains `merge_ready: true` with no `blocker`/`high`
   findings under the severity gate.

## 5. Candidate files to touch (Builder will create / edit)

> All paths are additive unless marked. Counts are upper bounds.

| Path                                                                                  | Type    | Approx count |
| ------------------------------------------------------------------------------------- | ------- | ------------ |
| `internal-rst-checker/fixtures/dns/**`                                                | new     | 6            |
| `internal-rst-checker/fixtures/dnssec/**`                                             | new     | 8            |
| `internal-rst-checker/fixtures/dnssec-ops/**`                                         | new     | 9            |
| `internal-rst-checker/fixtures/rde/**`                                                | new     | 32           |
| `internal-rst-checker/fixtures/rdap/**`                                               | new     | 32           |
| `internal-rst-checker/fixtures/srsgw/**`                                              | new     | 36           |
| `internal-rst-checker/fixtures/idn/**`                                                | new     | 5            |
| `internal-rst-checker/fixtures/integration/**`                                        | new     | 13           |
| `internal-rst-checker/fixtures/README.md`                                             | new     | 1            |
| `internal-rst-checker/tests/_fixtures/__init__.py`                                    | new     | 1            |
| `internal-rst-checker/tests/_fixtures/test_suite_fixtures_present.py`                 | new     | 1            |
| `docs/epp-spec-to-test-mapping.md`                                                    | append  | 1 edit       |

Estimated total: ~145 new files, 1 edited file. No deletions.

## 6. Risks and assumptions

### Risks

- **R1 (medium):** Fixture realism vs. safety. Some suites (RDE, DNSSEC-Ops,
  SRSGW) reference live infrastructure (PGP keys, TSIG secrets, registrar
  certificates). Builder must use clearly synthetic placeholders only and
  guard with the new `test_no_real_secrets_committed` check, otherwise we
  risk shipping look-alike credentials.
- **R2 (medium):** Schema drift. The spec declares schemas for many
  parameters (`inc/<suite>/inputs.yaml`). If we hand-write JSON that does
  not validate, we ship misleading examples. Mitigation: Builder will run
  the existing JSON schema validator
  (`.venv/bin/jsonschema`/`xmlschema-validate`) for every JSON/XML fixture
  before commit.
- **R3 (low):** Volume of new files (~145). Mitigation: split commits per
  suite (one commit per top-level fixture folder + one for tests/docs) so
  reviewers can scan each suite independently.
- **R4 (low):** Naming collision with future spec churn (e.g. `srsgw-07`
  came back). Mitigation: `case_id` strings in the manifest match the spec
  IDs verbatim, so a future re-add only needs a new entry.

### Assumptions

- **A1:** `internal-rst-checker/fixtures/<suite>/` is allowed to grow new
  folders without adjusting `Makefile` or CI (the fixtures path is referenced
  only by tests, which discover via the manifest).
- **A2:** The "if applicable" cases (`rdap-02`, `rdap-06`, `srsgw-02..03`,
  `srsgw-09..12`, `srsgw-13..15`, `idn-02`, `integration-04`,
  `integration-05`) still need fixtures — the skip is decided at runtime
  by input parameters, not by absence of fixtures. Builder will ship them
  and document the skip condition in the per-case README row.
- **A3:** `rde-12` (NNDN) is currently `Implemented: false` in the spec but
  still in scope per the user goal; we keep a fixture pair for it.
- **A4:** No live network or external services are required to validate
  these fixtures — they are static request/response samples consumed by
  smoke tests only.
- **A5:** PR strategy: one follow-up PR titled
  `fixtures(suites): complete .th fixture set for DNS/DNSSEC/RDE/RDAP/SRSGW/IDN/Integration`,
  branching from `main`, separate from PR #22 which only handled EPP.

## 7. Out of plan / explicit defer list

- Wiring the new fixtures into rule-driven assessors (analogous to
  `assess_epp02_greeting`). That is a follow-up implementation task once
  the fixtures land.
- Generating real RYDE bundles, real PGP signatures, or real EPP TLS
  certs. Only `.example` placeholders here.
- Adding new dashboard sections beyond what already exists. The dashboard
  already snapshots fixture presence indirectly via test counts; no new
  reporting logic in this work item.

## 8. Handoff request to Human

Please confirm:

- [ ] §2 case inventory matches your expectation (especially the
      "if applicable" entries we are keeping in scope).
- [ ] §3.1 directory layout and naming convention are acceptable
      (folder per case, `*.success.*` / `*.failure.*` suffix).
- [ ] §3.3 single guard-test module location
      (`internal-rst-checker/tests/_fixtures/`) is acceptable, or you
      prefer per-suite test files mirroring
      `internal-rst-checker/tests/epp/test_epp_th_fixtures_present.py`.
- [ ] §5 expected file count (~145 new files in 1 PR) is acceptable, or
      we should split into smaller PRs (per suite).

Once approved, Builder may proceed using
`docs/agent-artifacts/fixtures-dns-dnssec-rde-rdap/build.md` to log work.

`merge_ready: false` (Plan stage only).
