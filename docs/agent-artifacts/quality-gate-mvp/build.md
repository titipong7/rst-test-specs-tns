# Pilot Build Notes

## Changed Areas

- Added Cursor workflow rules under `.cursor/rules/`.
- Added role skill templates under `.cursor/skills/`.
- Added hook reminder in `.cursor/hooks.json` and `.cursor/hooks/quality-gate-reminder.sh`.
- Added workflow documentation under `docs/`.
- Updated `Makefile` with `quality-gate` and `quality-gate-python` targets.

## Commands Used

- `.venv/bin/pytest -q tests`
- `make lint`

## Known Limitations

- `make lint` requires Perl module `ICANN::RST::Spec` in local environment.
- Hook currently reminds before `git commit`; it does not auto-run tests.
