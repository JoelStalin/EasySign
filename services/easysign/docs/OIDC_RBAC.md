# OIDC, roles y aislamiento por empresa (ES-005)

Reemplaza el token de administrador provisional. Todo **falla cerrado**: sin autenticador configurado, cada llamada protegida responde 503.

## Roles
| Rol | Alcance |
|---|---|
| `platform_admin` | Todo, todas las empresas. Único rol que escribe el registro de certificados. |
| `tenant_admin` | Lectura y escritura dentro de **su** empresa; lee la auditoría de su empresa. |
| `tenant_operator` | Lectura y escritura de solicitudes y consentimientos de su empresa; **no** lee el libro de auditoría. |
| `auditor` | Solo lectura de su empresa (solicitudes, evidencia, consentimientos, auditoría). |

Los roles de empresa necesitan el claim de empresa (`tenant_id` por defecto). Un token sin él no coincide con ninguna empresa. Los roles desconocidos no conceden nada.

## Política por ruta
- **Registro de certificados** (`POST/…/suspend|reactivate|revoke`, `history`): solo `platform_admin`. Las lecturas siguen siendo públicas.
- **Consentimientos**: escribir `platform_admin|tenant_admin|tenant_operator` sobre su empresa; leer además `auditor`.
- **Libro de auditoría**: `platform_admin|tenant_admin|auditor`. Un rol de empresa solo ve su empresa, **pida lo que pida**; la exportación de otra empresa da 403.
- **Solicitudes de firma** (crear, enviar, subir documento, reemitir, cancelar, siguientes tokens): escritura de su empresa; leer y evidencia incluye `auditor`. La solicitud de otra empresa responde **404** (indistinguible de un id inexistente).
- **Rutas del firmante** (`/sign/...`, `/v1/signature-workflows/:id/signers/...`): no usan OIDC; usan el token de un solo uso del firmante.

## Validación del token
Emisor (`iss`), audiencia (`aud`), firma (JWKS), expiración (tolerancia 30 s) y `sub` obligatorios. Solo algoritmos asimétricos (RS256/384/512, ES256/384, PS256): se rechazan `alg: none` y los tokens HMAC (confusión de clave). Cualquier fallo es un 401 genérico (no se revela el motivo).

## Configuración
| Variable | Uso |
|---|---|
| `EASYSIGN_OIDC_ISSUER`, `EASYSIGN_OIDC_AUDIENCE`, `EASYSIGN_OIDC_JWKS_URI` | Los tres activan OIDC |
| `EASYSIGN_OIDC_ROLES_CLAIM` | Ruta con puntos al claim de roles, p. ej. `roles` o `realm_access.roles` (Keycloak). Admite lista o texto separado por espacios |
| `EASYSIGN_OIDC_TENANT_CLAIM` | Claim de la empresa (por defecto `tenant_id`; admite ruta con puntos) |
| `EASYSIGN_ADMIN_TOKEN` | Token estático provisional. **Con OIDC activo queda desactivado** salvo `EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN=true` (emergencia) |

## Auditoría
El actor es el `sub` del token. Un intento denegado se registra en el libro de **quien lo intentó** (con `targetTenant` en los detalles), no en el de la empresa objetivo: una empresa no puede ensuciar la auditoría de otra.

## Pendiente
- Revocación/introspección de tokens y cierre de sesión (hoy solo expiración corta).
- Claves de API por empresa para clientes máquina y su rotación.
- Administración de usuarios y roles (se delega al proveedor OIDC).
- Verificación contra un IdP real (Keycloak/otro); las pruebas usan un JWKS local firmado en el momento.
