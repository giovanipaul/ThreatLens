# ThreatLens

ThreatLens is a Python security log analyzer that will normalize authentication
events, identify suspicious activity, and present prioritized alerts through a
searchable dashboard.

## Current Status

The project currently includes a FastAPI foundation and a Linux authentication
log parser. The parser normalizes supported OpenSSH login events while safely
skipping malformed or unrelated entries.

## Implemented Features

- Parse successful and failed OpenSSH authentication events
- Recognize invalid-user login attempts
- Normalize timestamps, hostnames, usernames, IP addresses, ports, and protocols
- Validate IPv4/IPv6 addresses and port ranges
- Skip malformed and unsupported log entries without crashing
- Detect repeated failures from one source IP within a configurable time window
- Assign medium or high severity based on the number of failed attempts
- Report targeted usernames in structured brute-force alerts
- Persist normalized events and alerts in SQLite using SQLAlchemy
- Prevent duplicate event and alert imports with deterministic fingerprints
- Filter stored events by result or source IP and alerts by severity
- Upload UTF-8 authentication logs through a validated FastAPI endpoint
- Query stored events and alerts through documented REST API endpoints
- Provide sample authentication logs for local development

## Run Locally

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Start the development server:

```bash
uvicorn app.main:app --reload
```

Open:

- API health check: <http://127.0.0.1:8000/health>
- Interactive API documentation: <http://127.0.0.1:8000/docs>

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/logs/import` | Parse an uploaded log, run detections, and persist results |
| `GET` | `/api/events` | Filter stored events by result or source IP |
| `GET` | `/api/alerts` | Filter generated alerts by severity |
| `GET` | `/health` | Confirm that the service is running |

## Run Tests

```bash
pytest
```
