# ThreatLens

[![CI](https://github.com/giovanipaul/ThreatLens/actions/workflows/ci.yml/badge.svg)](https://github.com/giovanipaul/ThreatLens/actions/workflows/ci.yml)
[![Security](https://github.com/giovanipaul/ThreatLens/actions/workflows/security.yml/badge.svg)](https://github.com/giovanipaul/ThreatLens/actions/workflows/security.yml)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)

ThreatLens is a security log analysis application that converts raw OpenSSH
authentication logs into normalized events and prioritized alerts. It combines
a FastAPI backend, configurable detection rules, SQLite persistence, an analyst
workflow, reporting APIs, and a responsive monitoring dashboard.

![ThreatLens security monitoring dashboard](docs/images/dashboard.png)

## Why This Project

Authentication logs are useful only when analysts can parse, correlate, and act
on them quickly. ThreatLens demonstrates a compact security-monitoring pipeline:
it accepts raw log data, validates and normalizes each event, runs multiple
detection strategies, stores results safely, and gives an analyst a focused
interface for reviewing and managing findings.

For a concise engineering narrative, measurable outcomes, and resume-ready
bullets, see the [portfolio case study](docs/PORTFOLIO.md). For system-design,
security, and behavioral preparation, see the
[interview guide](docs/INTERVIEW.md).

## Key Features

- Parses successful, failed, and invalid-user OpenSSH authentication events
- Normalizes timestamps, hosts, usernames, IP addresses, ports, protocols, and results
- Validates IPv4/IPv6 addresses and safely skips malformed or unsupported lines
- Detects brute-force attempts from repeated failures by one source
- Detects password spraying across multiple targeted usernames
- Correlates successful logins with preceding failures from the same source
- Assigns structured severity levels and records targeted users and attempt counts
- Prevents duplicate imports using deterministic SHA-256 fingerprints
- Persists events, alerts, and analyst status changes in SQLite with SQLAlchemy
- Supports open, acknowledged, and resolved alert workflows
- Filters telemetry and alerts by result, source IP, severity, and status
- Exports filtered events and alerts as CSV or JSON
- Provides an accessible, responsive analyst dashboard and OpenAPI documentation
- Authenticates users with salted scrypt password hashes and database-backed sessions
- Enforces analyst read access and administrator-only import/workflow mutations
- Supports password rotation, administrator-managed accounts, and session revocation
- Protects mutations with CSRF tokens and throttles repeated login failures
- Audits authentication, account administration, imports, and alert actions
- Preserves append-only alert investigation history with analyst notes and transitions
- Emits structured JSON request and import logs with traceable request IDs
- Exposes Prometheus metrics plus separate liveness and database-readiness probes
- Scans source, dependencies, and pull-request changes for security issues
- Publishes versioned, provenance-attested containers from semantic version tags
- Runs locally or in Docker with persistent storage
- Validates every push with Ruff, Pytest, and a Docker build in GitHub Actions

## Architecture

```mermaid
flowchart LR
    A[OpenSSH auth log] --> B[Validated upload API]
    B --> C[Linux auth parser]
    C --> D[Normalized security events]
    D --> E[Detection engine]
    E --> F[Structured security alerts]
    D --> G[(SQLite)]
    F --> G
    G --> H[FastAPI query and report APIs]
    H --> I[Analyst dashboard]
    I --> J[Open / Acknowledged / Resolved]
```

The application keeps parsing, detection, persistence, API, and presentation
responsibilities separate so that each layer remains independently testable.

## Detection Rules

| Rule | Signal | Output |
|---|---|---|
| Brute force | Repeated failures from one source within a configurable window | Medium or high alert with attempt count and targeted users |
| Password spray | One source attempts authentication across several usernames | Structured password-spraying alert |
| Suspicious success | A successful login follows repeated failures from the same source | Correlated successful-login alert |

Thresholds and time windows are defined in the detection modules and can be
adjusted through validated environment settings without changing code.

## Configuration

Copy `.env.example` to `.env` for Docker Compose, or export the settings before
starting Uvicorn. ThreatLens validates every numeric setting during startup and
fails clearly when a value is malformed or outside its safe range.

| Variable | Default | Purpose |
|---|---:|---|
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed attempts required from one source |
| `BRUTE_FORCE_WINDOW_SECONDS` | `300` | Brute-force correlation window |
| `PASSWORD_SPRAY_USER_THRESHOLD` | `5` | Unique usernames required for a spray alert |
| `PASSWORD_SPRAY_WINDOW_SECONDS` | `600` | Password-spray correlation window |
| `SUSPICIOUS_SUCCESS_FAILURE_THRESHOLD` | `3` | Failures required before a successful login |
| `SUSPICIOUS_SUCCESS_WINDOW_SECONDS` | `600` | Suspicious-success correlation window |
| `MAX_UPLOAD_MB` | `2` | Maximum uploaded log size |
| `MAX_LOG_LINES` | `50000` | Maximum lines accepted per import |
| `THREATLENS_LOG_LEVEL` | `INFO` | Structured application log verbosity |
| `THREATLENS_VERSION` | `dev` | Version displayed in OpenAPI metadata |

## Quick Start

### Requirements

- Python 3.13
- `pip`
- Docker Desktop (optional)

### Run locally

```bash
git clone https://github.com/giovanipaul/ThreatLens.git
cd ThreatLens
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export THREATLENS_ADMIN_USERNAME=admin
export THREATLENS_ADMIN_PASSWORD='replace-with-a-long-unique-password'
uvicorn app.main:app --reload
```

Open:

- Dashboard: <http://127.0.0.1:8000/>
- Interactive API documentation: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>
- Database readiness: <http://127.0.0.1:8000/ready>
- Prometheus metrics: <http://127.0.0.1:8000/metrics>

### Run with Docker

```bash
cp .env.example .env
export THREATLENS_ADMIN_USERNAME=admin
export THREATLENS_ADMIN_PASSWORD='replace-with-a-long-unique-password'
docker compose up --build
```

SQLite data is retained in the local `data/` directory. Stop the application
with:

```bash
docker compose down
```

## Database Migrations and PostgreSQL

ThreatLens applies versioned Alembic migrations automatically during startup.
Existing pre-Alembic SQLite databases are safely baselined without deleting
stored events, alerts, users, sessions, or audit history.

Migration commands are also available for development:

```bash
alembic current
alembic upgrade head
alembic downgrade -1
```

SQLite remains the zero-configuration default. To use PostgreSQL, create a
database and provide a psycopg SQLAlchemy URL:

```bash
export THREATLENS_DATABASE_URL='postgresql+psycopg://threatlens:password@localhost/threatlens'
uvicorn app.main:app
```

CI exercises the repository and migrations against PostgreSQL 17 in addition
to the default SQLite suite.

## Sample Walkthrough

1. Start ThreatLens locally or with Docker.
2. Open the dashboard.
3. Select `sample_data/auth.log`.
4. Keep the displayed log year or enter the year represented by the sample.
5. Choose **Import and analyze**.
6. Review normalized success and failure events.
7. Inspect the generated brute-force alert.
8. Acknowledge, resolve, or reopen the alert.
9. Filter the tables or export the results as CSV or JSON.

Importing the same file again does not duplicate stored events or alerts.
For a presentation-ready sequence and talking points, see the
[five-minute demo guide](docs/DEMO.md).

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/logs/import` | Parse an uploaded log, run detections, and persist results |
| `GET` | `/api/events` | Filter stored events by result or source IP |
| `GET` | `/api/alerts` | Filter alerts by severity or analyst status |
| `PATCH` | `/api/alerts/{id}/status` | Acknowledge, resolve, or reopen an alert |
| `GET` | `/api/alerts/{id}/history` | Review immutable analyst investigation history |
| `GET` | `/api/reports/events.csv` | Download filtered events as CSV |
| `GET` | `/api/reports/events.json` | Download filtered events as JSON |
| `GET` | `/api/reports/alerts.csv` | Download filtered alerts as CSV |
| `GET` | `/api/reports/alerts.json` | Download filtered alerts as JSON |
| `GET` | `/health` | Confirm that the service is running |
| `GET` | `/ready` | Confirm that the service and database are ready |
| `GET` | `/metrics` | Scrape Prometheus-compatible operational metrics |

All dashboard and `/api` routes require a database-backed login session except
the public login, liveness, readiness, and metrics endpoints. Analyst accounts
can view and export events and alerts. Administrators can additionally import
logs and change alert status. The bootstrap administrator is created once from
`THREATLENS_ADMIN_USERNAME` and `THREATLENS_ADMIN_PASSWORD`; changing those
variables later does not overwrite its stored password.

For HTTPS deployments, set `THREATLENS_SECURE_COOKIES=true`. Session lifetime
defaults to 12 hours and can be set to a positive number of hours with
`THREATLENS_SESSION_HOURS`.

Analysts and administrators can acknowledge, resolve, or reopen alerts with an
optional investigation note. ThreatLens preserves the analyst identity,
timestamp, previous state, and new state and displays the complete history from
the dashboard.

The **Account** page lets users change their own password and lets administrators
create, enable, disable, and assign roles to accounts or revoke their sessions.
Administrator audit data is available from `GET /api/admin/audit`.

## Observability

ThreatLens emits application logs as newline-delimited JSON. Each request gets
an `X-Request-ID` response header; a caller-supplied ID is preserved when it
contains only letters, numbers, `.`, `_`, or `-` and is no longer than 128
characters. Request logs include the route template, status, and duration
without recording credentials, session tokens, request bodies, or query values.

`/metrics` exposes low-cardinality HTTP request totals and latency histograms,
plus import totals, duration, parsed and stored event counts, and generated and
stored alert counts. `/health` is a process liveness probe, while `/ready`
performs a database query. The Docker health check uses `/ready`.

## Security and Releases

The Security workflow runs Bandit, audits every pinned Python dependency, scans
the source with CodeQL, and reviews dependency changes in pull requests.
Dependabot proposes weekly updates for Python, GitHub Actions, and the base
container image.

Semantic version tags such as `v1.0.0` trigger a gated release workflow. After
lint, tests, PostgreSQL integration coverage, and security checks pass, the
workflow publishes versioned images to GitHub Container Registry, attaches
build-provenance attestations, and creates a GitHub release with generated
notes. See the [release checklist](docs/RELEASING.md).

## Project Structure

```text
ThreatLens/
├── app/
│   ├── api/          # FastAPI routes and dependencies
│   ├── detection/    # Brute-force, spray, and correlation rules
│   ├── models/       # Validated domain models
│   ├── migrations/   # Versioned Alembic database schema
│   ├── parsers/      # OpenSSH log normalization
│   ├── schemas/      # Request and response schemas
│   ├── services/     # CSV and JSON reporting
│   ├── static/       # Dashboard JavaScript and CSS
│   ├── storage/      # SQLAlchemy records and repository
│   └── templates/    # Jinja2 dashboard
├── sample_data/      # Safe demonstration log
├── tests/            # Unit, API, detection, and persistence tests
├── Dockerfile
├── alembic.ini
├── compose.yaml
└── requirements.txt
```

## Quality Checks

Run the complete test suite:

```bash
pytest
```

Run static analysis:

```bash
ruff check .
```

Build the container:

```bash
docker build -t threatlens .
```

The suite covers parsing, detection, persistence, reporting, API behavior,
upload boundaries, and alert lifecycle management. GitHub Actions enforces a
minimum of **95% application-code coverage** on every push. The separate
Security workflow runs on pushes, pull requests, a weekly schedule, and manual
dispatch.

## Security Decisions and Limitations

- Uploads are limited to UTF-8 `.log` and `.txt` files no larger than 2 MB.
- Passwords use uniquely salted scrypt hashes and must be at least 12 characters.
- Only SHA-256 digests of random session tokens are persisted; cookies are
  HttpOnly and SameSite Strict.
- Malformed records are skipped instead of crashing an import.
- Deterministic fingerprints prevent duplicate records without storing raw logs.
- SQLAlchemy handles database queries rather than interpolated SQL.
- Sample data uses documentation-only IP ranges and contains no real credentials.
- ThreatLens is a portfolio project, not a production SIEM. It does not provide
  multi-tenant data isolation, live log streaming, distributed processing, or
  encrypted database storage.

See [Security Notes](docs/SECURITY.md) for trust boundaries and safe-use guidance.

## Future Improvements

- Ingest additional formats such as systemd journal and Windows events
- Stream events from monitored hosts rather than relying only on file uploads
- Add alert assignment and investigation ownership
- Add charts for trends and source-IP activity
- Add shared rate limiting and centralized metrics for multi-worker deployments
