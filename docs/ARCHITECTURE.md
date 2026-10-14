# EasySign architecture

Independent multi-tenant trust services platform; EasyCount is an API client, not a database peer.

## GetUpPay-inspired patterns
- Public REST edge; internal gRPC contracts as services are extracted.
- Transactional outbox and Kafka for durable domain events (planned).
- PostgreSQL with tenant-scoped authorization (planned).
- OIDC/OAuth2 identity, audit trails, immutable document evidence (planned).
- Dedicated signing adapter with HSM/PKCS#11 or authorized trust providers.
- WhatsApp Business Platform adapter with consent and short-lived links.

## Security gates
The initial API is intentionally sandbox-only. No real signatures, keys, biometric capture, DGII submissions or accreditation claims are implemented. Never expose this skeleton publicly without authentication and security hardening.
