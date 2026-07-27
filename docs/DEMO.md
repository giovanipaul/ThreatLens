# ThreatLens Demo Guide

This walkthrough presents the complete analyst workflow in about five minutes
using only documentation-range IP addresses and the bundled sample log.

## Prepare

Copy the example environment and replace the bootstrap password before starting:

```bash
cp .env.example .env
```

Set these values in `.env`:

```dotenv
THREATLENS_ADMIN_USERNAME=admin
THREATLENS_ADMIN_PASSWORD=replace-this-with-a-unique-demo-password
```

Start the application and wait for the database readiness check:

```bash
docker compose up --build -d
curl --fail http://127.0.0.1:8000/ready
```

Open <http://127.0.0.1:8000/> and sign in with the credentials from `.env`.

## Five-minute walkthrough

1. Show that the dashboard redirects anonymous visitors to the login page.
2. Sign in as the bootstrap administrator and point out the displayed role.
3. Import `sample_data/auth.log` and use the current sample year.
4. Explain the normalized authentication events and generated brute-force alert.
5. Acknowledge the alert with an investigation note, then open its history.
6. Filter the event and alert tables and export one report.
7. Open the Account page and show user provisioning, roles, and session revocation.
8. Open `/metrics` and identify request, import, event, and alert telemetry.
9. Open `/ready` to distinguish database readiness from `/health` liveness.

## Talking points

- Parsing, detection, persistence, API, and presentation are separate and tested.
- Passwords use salted scrypt hashes; only session-token digests are stored.
- Analysts have read/export access while administrators control mutations.
- Alert transitions are append-only and preserve actor, timestamp, and notes.
- Imports are bounded, validated, idempotent, audited, and observable.
- SQLite supports a zero-configuration demo; PostgreSQL is exercised in CI.
- Tagged releases publish an attested container to GitHub Container Registry.

## Reset

Stop the demo:

```bash
docker compose down
```

To start with an empty local database, remove `data/threatlens.db` manually only
after confirming that no demo data needs to be retained.
