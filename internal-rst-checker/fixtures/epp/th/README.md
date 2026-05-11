# .th EPP Fixtures (THNIC)

This directory contains standalone XML fixtures for EPP testing against `.th`.

## Connection template

Use `th.env.example` as your local template:

- `EPP_HOST=epp.thains.co.th`
- `EPP_PORT=700`
- `EPP_USERNAME=THNIC-20001`
- `EPP_PASSWORD=<set-locally>`

Do not commit real credentials.

## Fixture files

- `01-hello.xml`
- `03-login-success.xml`
- `03-login-failure.xml`
- `04-domain-check-success.xml`
- `04-domain-check-failure.xml`
- `14-domain-create-success.xml`
- `14-domain-create-failure.xml`
- `16-domain-update-success.xml`
- `16-domain-update-failure.xml`
- `18-domain-renew-success.xml`
- `18-domain-renew-failure.xml`
- `19-domain-transfer-request-success.xml`
- `19-domain-transfer-request-failure.xml`
- `20-domain-transfer-reject-success.xml`
- `20-domain-transfer-reject-failure.xml`
- `21-domain-delete-success.xml`
- `21-domain-delete-failure.xml`
- `26-wide-glue-policy.xml`
- `27-glueless-internal-host-create.xml`
- `27-glueless-internal-host-delegate.xml`

## Placeholder conventions

- Replace `example.th` and related hostnames with your test objects.
- Replace `AUTH-CODE` with a valid transfer code for your test domain.
- Keep `clTRID` unique per transaction in real runs.
