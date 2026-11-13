# Registro público de certificados y revocación

Cubre A-02, A-10 y B-10/B-11 de `docs/INDOTEL_REQUIREMENTS.md` (Res. INDOTEL 067-2025: Anexo II art. 31; Anexo I art. 36.2 m-n y 36.3).

## Garantías
- **Solo se agrega, nunca se borra.** Cada evento (`issued`, `suspended`, `reactivated`, `revoked`) se encadena con SHA-256 al anterior. Si el archivo se altera, el servicio no arranca (`CHAIN_BROKEN`).
- **Disponible tras el vencimiento.** Un certificado vencido sigue consultable con su último estado y `expired: true`.
- **Revocación final.** Un certificado revocado no se reactiva. La suspensión (`certificateHold`) sí es reversible.
- **Plazo de 24 h.** `requestedAt` es cuándo se pidió la revocación; la publicación es inmediata. Si pasan más de 24 h, `withinSla: false` y aparece en `slaBreaches()` para monitoreo.

## API
| Método y ruta | Acceso |
|---|---|
| `GET /v1/registry/certificates?status=&limit=&offset=` | Público |
| `GET /v1/registry/certificates/:serial` | Público |
| `GET /v1/registry/revocations` | Público (lista JSON de revocados) |
| `POST /v1/registry/certificates` | Administrador |
| `POST /v1/registry/certificates/:serial/{suspend,reactivate,revoke}` | Administrador |
| `GET /v1/registry/certificates/:serial/history` | Administrador |

## Configuración
| Variable | Uso |
|---|---|
| `EASYSIGN_REGISTRY_FILE` | Archivo JSONL de persistencia. Sin él, el registro vive solo en memoria. |
| `EASYSIGN_ADMIN_TOKEN` | Token `Bearer` para escrituras. Sin él, las escrituras responden 503 (fallan cerradas). Control provisional hasta OIDC/RBAC (ES-005). |

## Pendiente
- **OCSP y CRL X.509 firmadas** (36.3): requieren la clave de la CA; la lista actual es JSON y no sustituye una CRL firmada.
- Estado accesible "de forma automatizada, fiable, gratuita y eficiente" bajo carga: pruebas de disponibilidad (ES-018).
- Almacenamiento en PostgreSQL con aislamiento por tenant (ES-006) en lugar de archivo.
- Integrar `verify_signature` de la cola con `verifyEcfXml` una vez fusionado el PR de firma real: hoy ese manejador solo comprueba la longitud del valor.
- `/v1/system/status` ahora informa `dgiiComplianceReady: false`: no se afirma cumplimiento hasta superar la validación oficial.
