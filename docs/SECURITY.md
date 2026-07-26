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
5. The authentication layer resolves hashed session tokens to active users.
6. Role checks allow analysts to read/export and administrators to mutate data.
7. The repository persists normalized events, alerts, workflow state, users,
   and sessions.
8. API responses and exports return structured stored data to the analyst.

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
- Uniquely salted scrypt password hashing with a 12-character minimum
- Random database-backed sessions that persist only SHA-256 token digests
- HttpOnly, SameSite Strict session cookies with optional HTTPS-only transport
- Administrator-only log imports and alert workflow changes
- Idempotent bootstrap administrator creation from environment variables

## Known Limitations

- No TLS termination within the application
- SQLite data is not encrypted at rest
- No malware scanning for uploaded files
- No rate limiting or per-user quotas
- No immutable analyst audit log
- No administrator UI or API for provisioning and deactivating users
- Detection is rule-based and limited to the supported OpenSSH formats
- The default development server is not intended for public production use

## Safe Deployment Guidance

If ThreatLens is extended beyond local demonstrations:

- Terminate TLS at a trusted reverse proxy and enable secure cookies.
- Restrict access to trusted networks and users.
- Use a unique bootstrap password of at least 12 characters, then protect the
  environment variables as secrets.
- Store data in an encrypted, access-controlled database.
- Add rate limiting, audit logging, and retention policies.
- Run the container as a non-root user with a read-only filesystem where possible.
- Review dependencies and container images regularly.
- Never upload logs containing sensitive data without authorization.
