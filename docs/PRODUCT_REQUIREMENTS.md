# EasySign — Product requirements (2026-10-14)

## Vision
GetUpSoft's independent digital trust SaaS, integrated with EasyCount via authenticated versioned APIs. Node.js/TypeScript, GetUpPay-inspired architectural boundaries. FastAPI prohibited.

## Capabilities
- Multi-tenant organization, users, role-based authorization and isolation.
- Electronic signatures with explicit consent and tamper-evident evidence.
- Certificate-backed digital signatures via authorized trust providers.
- Document upload, immutable versions, signer sequencing and validation.
- WhatsApp Business Platform notification, approved templates, opt-in, one-time verification URLs.
- Identity verification, documentary checks, liveness and human review via lawful approved providers.
- EasyCount e-CF XML signing service with DGII official schemas and conformance vectors.
- Independent SaaS billing, API keys/OAuth, usage and customer-facing verification portal.

## Regulatory gates
Research INDOTEL Ley 126-02 and Res. 067-2025, DGII Ley 32-23 and technical specifications, privacy Ley 172-13, WhatsApp platform policies. Do not equate liveness or OTP with legally recognized digital signature. No CA operation without relevant authorization.

## Nonfunctional
Secure by default; zero trust; encryption; no raw private keys in app; tenant separation; auditable consent; accessible UX; idempotency; immutable evidence; RPO target 15 min and RTO target 2 h, subject to validation. Target availability 99.9% after production readiness.

## Architecture
REST/OpenAPI edge; gRPC for selected internal boundaries; PostgreSQL transactional state; Kafka with transactional outbox; Redis optional; OIDC/Keycloak; HSM/PKCS#11 or authorized external signing; S3-compatible retention-controlled evidence; OpenTelemetry.

## Product interfaces
Public portal, business portal, mobile signer journey, administrative compliance portal, API/SDK. EasyCount remains responsible for tax document generation and DGII submission; EasySign signs and verifies authorized XML.
