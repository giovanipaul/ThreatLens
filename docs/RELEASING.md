# Releasing ThreatLens

ThreatLens releases follow semantic version tags in the form `vMAJOR.MINOR.PATCH`.
The release workflow reruns lint, tests, PostgreSQL integration coverage, Bandit,
and dependency auditing before publishing anything.

## Release checklist

1. Confirm `master` is clean, synchronized, and green in CI and Security.
2. Review dependency and CodeQL alerts.
3. Update documentation for user-visible changes.
4. Choose the semantic version based on compatibility.
5. Create and push an annotated tag:

   ```bash
   git tag -a v1.0.0 -m "ThreatLens v1.0.0"
   git push origin v1.0.0
   ```

6. Confirm the Release workflow publishes:

   - a GitHub release with generated notes;
   - semantically tagged images under `ghcr.io/giovanipaul/threatlens`;
   - GitHub build-provenance attestation for the image digest.

7. Pull the immutable version tag and verify readiness before announcing it.

Do not reuse or move an existing release tag. Correct a release with a new patch
version so the published source, image, and provenance remain auditable.
