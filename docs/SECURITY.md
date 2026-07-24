# ThreatLens Security Notes

## Intended Use

ThreatLens is an educational portfolio application for analyzing sample or
authorized OpenSSH authentication logs. It should not be exposed directly to
the public internet or treated as a replacement for a production SIEM.

## Trust Boundaries

1. A user supplies an authentication log through the dashboard or API.
2. The upload layer validates the extension, content encoding, and size.
3. The parser accepts supported OpenSSH patterns and skips malformed input.
4. Detection modules operate only on validated `SecurityEvent` models.
5. The repository persists normalized events, alerts, and workflow state.
6. API responses and exports return structured stored data to the analyst.

## Implemented Safeguards

- Maximum upload size of 2 MB
- UTF-8 text and supported-extension validation
- Pydantic validation for normalized data
- IP address and port validation
- Graceful handling of malformed log lines
- SQLAlchemy-based persistence
- SHA-256 fingerprints for duplicate prevention
- No real credentials or routable source addresses in sample data
- Automated tests and static analysis on every GitHub push

## Known Limitations

- No user authentication, authorization, or role-based access control
- No TLS termination within the application
- SQLite data is not encrypted at rest
- No malware scanning for uploaded files
- No rate limiting or per-user quotas
- No immutable analyst audit log
- Detection is rule-based and limited to the supported OpenSSH formats
- The default development server is not intended for public production use

## Safe Deployment Guidance

If ThreatLens is extended beyond local demonstrations:

- Place it behind an authenticated reverse proxy with TLS.
- Restrict access to trusted networks and users.
- Store data in an encrypted, access-controlled database.
- Add rate limiting, audit logging, and retention policies.
- Run the container as a non-root user with a read-only filesystem where possible.
- Review dependencies and container images regularly.
- Never upload logs containing sensitive data without authorization.

