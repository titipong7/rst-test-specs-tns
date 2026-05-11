# Pilot Review Findings

## Blocker

1. **Missing lint runtime dependency**
   - Severity: `blocker`
   - Evidence: `make lint` fails with missing `ICANN::RST::Spec` Perl module.
   - Required action: document/install Perl dependencies in developer setup and CI image.

## Medium

1. **Quality gate command assumes local tooling parity**
   - Severity: `medium`
   - Evidence: `quality-gate` calls both Perl lint and Python tests without environment checks.
   - Suggested action: add preflight checks or a bootstrap target.

## Merge Readiness

`merge_ready: false` until blocker is resolved or explicitly waived for docs-only usage.
