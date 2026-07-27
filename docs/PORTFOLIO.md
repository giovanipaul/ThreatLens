# ThreatLens Portfolio Case Study

## Project summary

ThreatLens is a security log analysis application that turns OpenSSH
authentication logs into normalized events, correlated detections, and an
auditable analyst workflow. It demonstrates backend engineering, application
security, database design, observability, testing, and release automation in one
cohesive project.

**Technology:** Python 3.13, FastAPI, Pydantic, SQLAlchemy, Alembic, SQLite,
PostgreSQL, Jinja2, JavaScript, Prometheus, Docker, and GitHub Actions.

**Repository:** <https://github.com/giovanipaul/ThreatLens>

## Problem and approach

Raw authentication logs are difficult to review consistently and provide no
built-in investigation workflow. ThreatLens separates that problem into
independently testable layers:

1. A bounded upload endpoint validates file type, size, line count, and UTF-8.
2. A parser converts supported OpenSSH records into validated domain models.
3. Three detection strategies identify brute force, password spraying, and a
   successful login following repeated failures.
4. A repository layer deduplicates and persists events, alerts, users, sessions,
   audit records, and immutable alert history.
5. Protected APIs and a dashboard support investigation, filtering, exports,
   account administration, and alert state transitions.
6. Operational endpoints, structured logs, metrics, CI, security scans, and
   gated releases make the application diagnosable and repeatable.

## Evidence-backed outcomes

- Maintains **98.29% application-code coverage**, above the enforced 95% gate.
- Passes **106 test cases**, including API, authentication, detection,
  persistence, migrations, observability, and PostgreSQL integration behavior.
- Implements **three correlation rules** with bounded, environment-validated
  thresholds and time windows.
- Enforces administrator and analyst roles across dashboard and API operations.
- Uses salted scrypt password hashes and stores only SHA-256 session-token
  digests in the database.
- Preserves actor, timestamp, prior state, new state, and notes for every alert
  transition.
- Supports zero-configuration SQLite and versioned Alembic migrations, while CI
  verifies the repository against PostgreSQL 17.
- Exposes low-cardinality Prometheus metrics, JSON request logs, request IDs,
  liveness, and database readiness.
- Runs Ruff, Pytest, Bandit, pip-audit, CodeQL, dependency review, Docker builds,
  and automated dependency updates through GitHub.
- Publishes semantically tagged, provenance-attested containers through a gated
  release workflow.

## Security decisions

### Authentication and authorization

Passwords are salted and hashed with scrypt. Random session tokens are returned
only to the client; the database stores their SHA-256 digests. Sessions expire,
can be revoked, and are invalidated when a user is disabled or changes a
password. Analyst and administrator roles are enforced in API dependencies, not
only hidden in the interface.

### Request and upload protection

State-changing requests require a double-submit CSRF token. Login attempts are
throttled per source address. Imports accept only bounded UTF-8 `.log` or `.txt`
files, and parsing operates on validated models. SQLAlchemy constructs database
queries without interpolated SQL.

### Auditability

Authentication, account administration, imports, and alert actions create audit
records. Alert history is append-only at the application layer and records the
analyst responsible for every transition.

## Engineering tradeoffs

- **SQLite and PostgreSQL:** SQLite keeps the demonstration simple, while the
  repository and migration design preserve a production-oriented PostgreSQL
  path. PostgreSQL is tested in CI rather than required for every local run.
- **Rule-based detection:** Explicit rules are explainable and deterministic,
  which is useful for testing and analyst review. The tradeoff is narrower
  coverage than streaming or behavioral detection systems.
- **Process-local login throttling:** This is sufficient for a single-process
  portfolio deployment. A multi-worker deployment should move rate limiting to
  a shared edge or data store.
- **Application-level audit immutability:** Alert history is append-only through
  the application, but a production system should add database permissions,
  retention controls, and tamper-evident external storage.
- **Public metrics:** Metrics expose operational counts and route templates but
  no credentials, tokens, bodies, or query values. A public deployment should
  restrict the metrics endpoint at the network layer.

## Resume-ready bullets

Choose two or three bullets that best match the target role.

### Backend and security

- Built a FastAPI security-log analysis platform that normalizes OpenSSH events,
  runs three correlation rules, prevents duplicate ingestion, and supports an
  auditable alert-investigation workflow across SQLite and PostgreSQL.
- Implemented secure authentication with salted scrypt hashes, database-backed
  sessions, CSRF protection, login throttling, analyst/admin RBAC, account
  administration, session revocation, and immutable alert transition history.
- Designed SQLAlchemy repositories and Alembic migrations for events, alerts,
  users, sessions, and audit records, with PostgreSQL integration tests and
  98%+ application-code coverage.

### DevSecOps and platform

- Added JSON request logging, traceable request IDs, Prometheus request/import
  metrics, and separate liveness and database-readiness probes for diagnosable
  container operation.
- Built GitHub Actions pipelines enforcing Ruff, 95%+ coverage, PostgreSQL
  integration tests, Bandit, pip-audit, CodeQL, dependency review, and Docker
  builds on repository changes.
- Automated semantic-version releases to GitHub Container Registry with
  generated release notes, container metadata, and build-provenance
  attestations; configured Dependabot for Python, Actions, and Docker updates.

## Scope statement

ThreatLens is a portfolio application, not a production SIEM. It intentionally
does not claim multi-tenant isolation, encrypted storage, distributed
processing, shared rate limiting, live agent ingestion, or tamper-proof external
audit retention. Those boundaries are documented and provide concrete next-step
design discussions.
