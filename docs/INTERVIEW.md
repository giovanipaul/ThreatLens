# ThreatLens Interview Guide

## Thirty-second introduction

ThreatLens is a Python and FastAPI security-log analysis application I built to
turn raw OpenSSH authentication logs into normalized events and explainable
alerts. It detects brute force, password spraying, and suspicious success after
failures, then gives authenticated analysts an auditable workflow to investigate
and export results. I treated it as a complete backend system: secure sessions
and RBAC, SQLAlchemy and Alembic across SQLite and PostgreSQL, structured
observability, 98%+ coverage, security scanning, Docker, and gated releases.

## Two-minute walkthrough

Start with the input boundary: an administrator uploads a bounded UTF-8 log.
The parser translates supported lines into Pydantic models and safely skips
malformed records. Three independent detectors correlate those events over
validated thresholds and windows. The repository uses deterministic
fingerprints to avoid duplicate events and alerts, then stores workflow state
and append-only transition history.

Users authenticate with database-backed sessions. Passwords use salted scrypt
hashes, only token digests are persisted, and API dependencies enforce analyst
or administrator access. CSRF protection covers mutations, account changes
revoke sessions where appropriate, and privileged operations are audited.

Operationally, each request has a request ID and structured JSON log. Prometheus
metrics track HTTP and import behavior, while `/health` and `/ready` separate
process liveness from database availability. CI tests SQLite and PostgreSQL,
enforces more than 95% coverage, scans source and dependencies, builds Docker,
and gates versioned container releases.

## Architecture questions

### Why separate parsing, detection, and persistence?

Each layer has a different reason to change. New log formats should not alter
detection rules; a new rule should not rewrite storage; and moving from SQLite
to PostgreSQL should not affect parsing. The separation also makes unit tests
fast and lets API tests focus on orchestration and authorization.

### How does deduplication work?

Events receive deterministic SHA-256 fingerprints from their original log line,
while alerts use stable identifying fields. Before insertion, the repository
queries existing fingerprints and stores only new records. Re-importing the
same file is therefore idempotent without retaining the uploaded file itself.

### Why support both SQLite and PostgreSQL?

SQLite provides a frictionless local demonstration. PostgreSQL represents a
more realistic concurrent deployment target. SQLAlchemy abstracts most
dialect differences, a UTC-aware type keeps timestamps consistent, Alembic
controls schema versions, and CI runs integration tests against PostgreSQL 17.

### Why distinguish liveness and readiness?

Liveness answers whether the process is running. Readiness executes a database
query and answers whether the application can serve data-dependent requests.
Keeping them separate prevents a transient database failure from being confused
with a dead application process.

## Security questions

### Why scrypt?

scrypt is deliberately memory- and CPU-intensive, making offline password
guessing more expensive than a fast general-purpose hash. Every stored password
uses a unique random salt, and password verification uses constant-time digest
comparison.

### Why hash session tokens in the database?

A stolen session table should not immediately provide reusable browser tokens.
The client receives a high-entropy random token, while the repository stores
only its SHA-256 digest and compares digests during lookup.

### Why use both SameSite cookies and CSRF tokens?

SameSite Strict reduces cross-site cookie sending but is a browser policy, not
the sole trust decision. A separate unpredictable token, compared between the
cookie and request header, provides explicit mutation protection and defense in
depth.

### Where is RBAC enforced?

FastAPI dependencies resolve the active session user and then require an
administrator for privileged routes. The dashboard reflects the role for user
experience, but authorization is enforced server-side on every protected API
operation.

### What security limitation would you address first?

For a multi-instance deployment, I would move login throttling to a shared
store or edge gateway and restrict metrics and administration endpoints at the
network layer. I would also use managed secrets, TLS termination, encrypted
storage, and externally tamper-evident audit retention.

## Reliability and testing questions

### What does the test strategy cover?

Unit tests cover parsers, each detector, reporting, authentication primitives,
configuration, and database types. Repository tests cover deduplication,
sessions, account operations, alert history, and migrations. API tests exercise
authorization, CSRF, uploads, filters, exports, and workflow mutations.
Observability tests verify request IDs, metrics, structured logs, and readiness.
CI additionally runs PostgreSQL integration behavior and a Docker build.

### Why enforce a coverage threshold?

Coverage is a guardrail against untested paths, not proof of correctness. The
95% gate makes regressions visible while behavior-focused tests and boundary
cases provide the actual confidence. The current suite is above 98%.

### How are configuration mistakes handled?

Detection thresholds, windows, upload bounds, session lifetime, and logging
level are parsed and validated during startup. Invalid or unsafe values fail
fast rather than silently changing detection behavior at runtime.

## STAR stories

### Secure authentication milestone

- **Situation:** The original dashboard and APIs had useful analysis features
  but lacked identity and authorization boundaries.
- **Task:** Add authentication without breaking imports, reports, or analyst
  workflows.
- **Action:** Added salted scrypt hashes, database-backed sessions, secure
  cookies, login/logout, CSRF protection, analyst/admin dependencies, bootstrap
  credentials, throttling, account administration, audit records, and tests.
- **Result:** Every dashboard and API operation now has an explicit access
  policy, while the existing analysis workflow remains intact.

### Database portability milestone

- **Situation:** Direct schema creation and SQLite-only assumptions limited
  controlled evolution.
- **Task:** Introduce versioned migrations and a credible PostgreSQL path while
  preserving existing data.
- **Action:** Added Alembic, baselined legacy databases safely, created
  dialect-aware UTC handling, and added PostgreSQL integration coverage.
- **Result:** Schema changes are repeatable, existing SQLite demonstrations keep
  working, and the same repository is validated against PostgreSQL in CI.

### Operational readiness milestone

- **Situation:** The application could be tested functionally but was difficult
  to diagnose as a running service.
- **Task:** Add useful telemetry without leaking sensitive or high-cardinality
  data.
- **Action:** Added bounded request IDs, JSON logs, route-template metrics,
  import counters and histograms, database readiness, and focused tests.
- **Result:** Operators can correlate requests, measure latency and imports, and
  distinguish process health from database availability.

## Questions to ask the interviewer

- How does your team separate security requirements from application feature
  requirements during design and review?
- What signals determine whether a service is ready for production at your
  organization?
- How are database migrations tested and coordinated across deployments?
- Which parts of your CI and release process provide the most value, and which
  are currently being improved?
- How do engineers receive feedback from security and operations after a
  service is deployed?
