# Libro de auditoría y evidencia

Cubre B-08 y A-11 de `docs/INDOTEL_REQUIREMENTS.md` (Res. INDOTEL 067-2025, Anexo I art. 36.2 j; Anexo II art. 33 i-j) y ES-007.

## Qué registra
- Toda petición que **modifica** `/v1/registry/*`, `/v1/consents*` o `/v1/audit/export`, incluidas las **denegadas** (401/503): id de correlación, empresa (`tenantId` del cuerpo, o `platform`), actor, acción, recurso, resultado y código HTTP.
- **Nunca se guardan cuerpos** de petición. Los detalles pasan por redacción: claves como `password`, `passphrase`, `token`, `secret`, `authorization`, `p12`, `apiKey`, `otp` se sustituyen por `[REDACTED]` y los textos largos se truncan.
- Cada respuesta lleva `X-Correlation-Id` (se respeta el de la petición si cumple `[A-Za-z0-9._-]{8,80}`; si no, se genera un UUID).

## Integridad
Append-only con cadena SHA-256, igual que el registro y los consentimientos. Si el archivo se altera, el servicio no arranca (`CHAIN_BROKEN`).

## Evidencia exportable
`POST /v1/audit/export {tenantId}` devuelve el paquete: eventos de esa empresa, `headHash` del libro completo al momento de exportar y `chainValid`. Es evidencia técnica; su valor probatorio ante un juez requiere conservar el archivo íntegro y, idealmente, anclar `headHash` con un sello de tiempo cualificado (pendiente, ver ETSI EN 319 421).

## API (Bearer `EASYSIGN_ADMIN_TOKEN`; sin token, 503)
`GET /v1/audit/events?tenantId=&action=&correlationId=&from=&to=&limit=` · `POST /v1/audit/export`

## Configuración
`EASYSIGN_AUDIT_FILE` (JSONL; sin él, solo memoria).

## Pendiente
- Cobertura de las rutas de transacciones y de las operaciones de firma (ahora solo las reguladas).
- Conservación tras el cese de actividades y retención definida por política (36.2 j): copia externa inmutable.
- Anclaje periódico del `headHash` en un sello de tiempo cualificado.
- PostgreSQL con aislamiento por empresa (ES-006).
