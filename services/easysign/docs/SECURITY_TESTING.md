# Test strategy and authorized pentesting

## Pyramid
Unit: domain rules, state transitions, consent and idempotency. Integration: PostgreSQL, outbox, providers with sandbox stubs. Contract: OpenAPI/Protobuf and webhook compatibility. E2E: signer journey and EasyCount XML flows with synthetic data. Resilience: concurrency, retries, provider outages, backup restore.

## Security tests
- OWASP ASVS and API Security Top 10 checklist.
- Broken object-level authorization and cross-tenant access.
- Authentication/session, replay, OTP brute force, expiring links, webhook signatures.
- SSRF, XXE/XML signature wrapping, XSS, CSRF, injection, malicious PDFs and oversized uploads.
- Certificate chain, OCSP/CRL, expired/revoked certificates, key access boundaries.
- Evidence integrity, retention/deletion, biometric privacy and consent.
- CI: static analysis, dependency scan, secret scan, SBOM and unit/integration tests.
- Staging: DAST and manual pentest **only against explicitly authorized scoped assets**; no attacks against DGII, INDOTEL, WhatsApp or third-party production systems.

## Release gate
Block on critical vulnerabilities; high findings require documented risk disposition, remediation and retest before production approval. Archive test reports, timestamps, scope, reproducible findings and remediation links.
