# Delivery plan

0. Legal discovery: INDOTEL Ley 126-02, Res. 067-2025, DGII Ley 32-23, Ley 172-13; verify current official requirements with counsel.
1. Foundation: OIDC, tenant isolation, RBAC, PostgreSQL, migrations, evidence ledger, OpenAPI, CI.
2. Signing: immutable documents, consent, workflow, certified-provider adapters, OCSP/CRL, HSM.
3. Identity: authorized KYC/liveness provider, human review, WhatsApp templates and one-time links.
4. EasyCount: authenticated DGII XML signing interface, official XSD and test-vector validation.
5. Production: threat modeling, SAST/SCA/DAST, key ceremonies, backup restore tests, security audit and regulatory gates.

## Acceptance
- No production service until authentication, audit, isolation, encryption and external assessment are verified.
- No certificate issuance without the necessary authorization.
- No claim of DGII compliance until official conformance tests pass.
