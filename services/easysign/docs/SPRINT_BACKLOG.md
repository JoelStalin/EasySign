# EasySign — Agile release backlog

All estimates provisional. Sprint length: 2 weeks. Regulatory approval and provider contracts are external dependencies, not assumed complete.

## Sprint 0 — Foundations and discovery
- ES-001 Validate INDOTEL/DGII compliance matrix with source and legal reviewer.
- ES-002 Document C4 architecture, ADRs, boundaries and data classification.
- ES-003 Establish Node.js CI, lint, format, tests, security scans and PR protection.
- ES-004 Model threat scenarios, tenant boundaries and signing authorization.

## Sprint 1 — Identity and tenant foundation
- ES-005 OIDC authentication and authorization.
- ES-006 PostgreSQL migrations, tenant scoped repositories and isolation tests.
- ES-007 Audit event storage and correlation IDs.

## Sprint 2 — Document workflow
- ES-008 Secure upload, malware scan and immutable document versions.
- ES-009 Signature request state machine, signer sequencing and consent.
- ES-010 Outbox, idempotency, Kafka event contracts.

## Sprint 3 — Signature adapters
- ES-011 Authorized trust-provider adapter and certificate validation.
- ES-012 PDF/XML signing conformance and evidence package.

## Sprint 4 — Identity and WhatsApp
- ES-013 WhatsApp Business Platform templates and secure verification links.
- ES-014 KYC/liveness provider adapter, consent and manual review.

## Sprint 5 — EasyCount integration
- ES-015 Authenticated XML signing API, official DGII XSD and test vectors.
- ES-016 EasyCount integration contract and end-to-end synthetic e-CF tests.

## Sprint 6 — Hardening and release candidate
- ES-017 DAST, independent authorized pentest, remediation and retest.
- ES-018 Backup restore, SLO, load, resilience and incident runbooks.
- ES-019 Product Owner review and independent acceptance evaluation.

Each issue requires Given/When/Then acceptance criteria, test evidence, security classification and dependencies. Do not advance regulated functions to production without authorization.
