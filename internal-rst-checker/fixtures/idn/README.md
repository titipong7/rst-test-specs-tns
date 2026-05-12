# IDN Suite Fixtures

Static EPP `<create>` samples for the `idn` test suite from
`inc/idn/cases.yaml` (ICANN RST `v2026.04`).

## Connection template

Use `idn.env.example` as your local template:

- `IDN_TLD_TABLE` — the IDN table tag (e.g. `th`).
- `IDN_VALID_LABEL` / `IDN_INVALID_LABEL` — A-labels used for the happy
  and negative paths of `idn-01`.
- `IDN_VARIANT_REGISTRANT` — registrant handle that owns the original
  label, used to drive variant-policy negative paths.
- `IDN_ASCII_ONLY_TLD` — TLD with `idnOnly = true` for `idn-02`.

Do not commit real credentials. `*.env` files inside
`internal-rst-checker/fixtures/**` are git-ignored; only `*.env.example`
templates are tracked.

## Fixture files (per test case)

| Spec case | Happy path                                  | Negative path                                                                              | Notes                                                                                                                  |
| --------- | ------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `idn-01`  | `01-label-validation/create.success.xml`    | `01-label-validation/create.failure.xml`, `01-label-validation/variant-create.failure.xml` | Two negative branches: invalid IDN label + variant create from incorrect registrant.                                   |
| `idn-02`  | _no spec-level happy fixture — see notes_   | `02-ascii-in-idn-only-tld/create.failure.xml`                                              | Spec only describes a reject path. The happy outcome is "the test is skipped if `idnOnly = false` for all TLDs".       |

`tests/idn/test_idn_fixtures_present.py` enforces presence and
well-formedness for every active spec case.

## Placeholder conventions

- A-labels use `xn--` synthetic strings; never substitute real punycode
  used by a live registrant.
- The U-label `ตัวอย่าง` is the Thai word for "example" — kept here only
  to make the fixture human-readable.
- Variant testing uses two distinct registrant handles
  (`registrant-1` vs. `different-registrant`) to drive the
  `IDN_VARIANT_SERVER_ACCEPTS_VARIANT_CREATE_FROM_INCORRECT_REGISTRAR`
  branch.
