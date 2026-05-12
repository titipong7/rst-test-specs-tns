# RDE Suite Fixtures

Static escrow samples for the `rde` test suite from
`inc/rde/cases.yaml` (ICANN RST `v2026.04`).

## Connection template

Use `rde.env.example` as your local template:

- `RDE_TLD` — TLD label associated with the deposit.
- `RDE_DEPOSIT_FILE` — path to the `.ryde` bundle under test.
- `RDE_SIGNATURE_FILE` — path to the `.sig` PGP signature.
- `RDE_PUBLIC_KEY_FILE` — path to the RSP's `.asc` public key.

Do not commit real credentials, real PGP keys or real escrow data.
`*.env` files inside `internal-rst-checker/fixtures/**` are git-ignored;
only `*.env.example` templates and `.example`-suffixed binary placeholders
are tracked.

## Fixture files (per test case)

| Spec case | Happy path                                    | Negative path                                  | Notes                                                                                          |
| --------- | --------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `rde-01`  | `01-deposit-filename/filename.success.txt`    | `01-deposit-filename/filename.failure.txt`     | Failure starts with `.` and uses an `.zip` extension violating the `.ryde` pattern.            |
| `rde-02`  | `02-signature/signature.success.sig.example`  | `02-signature/signature.failure.sig.example`   | Both files are clearly synthetic placeholders; do not treat as real PGP signatures.            |
| `rde-03`  | `03-decrypt/deposit.success.ryde.example`     | `03-decrypt/deposit.failure.ryde.example`      | Failure represents a deposit encrypted with the wrong public key (`RDE_DECRYPTION_FAILED`).    |
| `rde-04`  | `04-xml-csv/deposit.success.{xml,csv}`        | `04-xml-csv/deposit.failure.{xml,csv}`         | Covers both XML well-formedness and CSV (RFC 4180) failures.                                   |
| `rde-05`  | `05-object-types/header.success.xml`          | `05-object-types/header.failure.xml`           | Failure declares an unregistered URI to trigger `RDE_UNEXPECTED_OBJECT_URI`.                   |
| `rde-06`  | `06-object-counts/header.success.xml`         | `06-object-counts/header.failure.xml`          | Failure overstates the domain count to trigger `RDE_OBJECT_COUNT_MISMATCH`.                    |
| `rde-07`  | `07-domain/domain.success.xml`                | `07-domain/domain.failure.xml`                 | Failure has invalid `name`, `roid`, future `crDate`, past `exDate`.                            |
| `rde-08`  | `08-host/host.success.xml`                    | `08-host/host.failure.xml`                     | Skipped if `epp.hostModel = attributes`. Failure violates `<host:name>` and `<addr>` rules.    |
| `rde-09`  | `09-contact/contact.success.xml`              | `09-contact/contact.failure.xml`               | Skipped if `general.registryDataModel = minimum`. Failure violates `cc`, `email`, `roid`, etc. |
| `rde-10`  | `10-registrar/registrar.success.xml`          | `10-registrar/registrar.failure.xml`           | Failure has empty `id` and non-numeric `gurid`.                                                |
| `rde-11`  | `11-idn-table/idn.success.xml`                | `11-idn-table/idn.failure.xml`                 | Failure references an unregistered IDN table tag and an invalid URL.                           |
| `rde-12`  | `12-nndn/nndn.success.xml`                    | `12-nndn/nndn.failure.xml`                     | Spec marks `Implemented: false`; fixtures kept for matrix continuity.                          |
| `rde-13`  | `13-epp-params/epp-params.success.xml`        | `13-epp-params/epp-params.failure.xml`         | Failure uses unregistered `objURI`/`extURI` to trigger the `*_UNEXPECTED_*` errors.            |
| `rde-14`  | `14-policy/policy.success.xml`                | `14-policy/policy.failure.xml`                 | Failure leaves `scope` empty and references an unknown element.                                |

`tests/rde/test_rde_fixtures_present.py` enforces presence and basic
syntactic validity for every active spec case.

## Placeholder conventions

- All XML uses synthetic `example.example` domains, `*-EXAMPLE` ROIDs,
  and clearly fake `H/D/C0000001` repository identifiers.
- `rde-12` (NNDN) is preserved despite being `Implemented: false` in
  `inc/rde/cases.yaml`; the fixtures will be ready when the case is
  re-enabled in a future spec revision.
