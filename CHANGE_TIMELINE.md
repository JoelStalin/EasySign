# EasySign — CHANGE_TIMELINE

Bitácora de cambios por bloque de trabajo. Cada entrada indica qué se hizo, qué falta y cómo revertir. El detalle operativo y de decisiones está en la memoria compartida (`~/.agents_shared_memory/sessions/2026-11-02-easysign-xmldsig-real.md`).

## 2026-11-02 Ruta A y luego B: de firma simulada a plataforma de firma electrónica

**Decisión del dueño del producto:** operar primero como Proveedor de Servicios de Firma Electrónica no cualificado (Res. INDOTEL 067-2025, Anexo II cap. III) y construir en paralelo la autorización como Entidad de Certificación. La Ruta A no sirve para firmar e-CF ante la DGII (exige certificado de una entidad autorizada por el INDOTEL).

**PR apilados (fusionar en este orden, solo con autorización; cada uno se revierte con `git revert <commit>`):**

| PR | Qué aporta | Commit |
|---|---|---|
| #10 | Firma XML-DSig real con certificados .p12 (antes era un hash simulado) | 36ae7c8 |
| #11 | Matriz de requisitos INDOTEL/DGII con artículo y estado | 79c807f |
| #12 | Registro público de certificados y revocación (log encadenado, plazo de 24 h) | 0642f0a |
| #13 | Libro de consentimientos y avisos legales del proveedor | 32cd513 |
| #14 | Libro de auditoría y evidencia con id de correlación | 5251693 |
| #15 | `verify_signature` real y auditoría de operaciones de firma | 78e76e6 |
| #16 | Flujo de solicitudes de firma, hoja de ruta A→B, paquete INDOTEL, plan de cese | 479e7b0 |
| #17 | Canal de entrega elegido por el cliente y QR en pantalla; página de firma | 7ace082 |
| #18 | Subida y visor del documento; el firmante debe abrirlo antes de firmar | f157af1 |

**Estado de las pruebas:** `npm run build && npm test` → 59/59 en la rama más alta de la pila. Nota: tras cambiar de rama en el ThinkCentre, borrar `dist/` antes de `npm test` (está ignorado y arrastra pruebas viejas).

**Límites declarados (no afirmar cumplimiento):**
- No hay cumplimiento DGII declarado: faltan XSD oficial, vectores de prueba y la regla del código de seguridad.
- Sin valor de firma digital: las firmas de este flujo son electrónicas no cualificadas.
- Identidad del firmante: el enlace/QR prueba posesión, no identidad civil (OTP pendiente).
- Correo y WhatsApp sin proveedor integrado (no envían; devuelven el enlace).
- Documentos guardados sin cifrar en reposo; retención y datos personales (Ley 172-13) por definir con el abogado.
- Control de acceso provisional por token de administrador hasta tener OIDC/RBAC; almacenamiento en archivos JSONL hasta tener PostgreSQL con aislamiento por empresa.

**Pendiente que necesita decisión o insumos del dueño:** datos legales de la sociedad (comunicación al INDOTEL, nada se envía sin su confirmación), proveedores de correo/WhatsApp y OTP, abogado/organismo de conformidad/aseguradora/HSM para la Ruta B, y autorización para fusionar a `main`.

**Revertir este bloque:** cerrar los PR sin fusionar, o revertir en orden inverso (#18 → #10). Esta bitácora es solo documentación.

## 2026-11-02 (continuación) Preguntas regulatorias del dueño del producto

| Pregunta | Respuesta (Res. INDOTEL 067-2025) | Dónde quedó | Commit |
|---|---|---|---|
| ¿Una persona física puede ser proveedora de firma? | No para Entidad de Certificación (Anexo II art. 12.1) ni para Proveedor de Servicios de Firma Electrónica (art. 27.1): se requiere persona jurídica. Sí para Unidad de Registro (art. 19.1). Pendiente confirmar Ley 126-02 y Reglamento 335-03 con abogado. | `docs/INDOTEL_REQUIREMENTS.md` (PR #11) | 0b2c377 |
| ¿La plataforma puede llamarse distinto de la sociedad (p. ej. GetUpSoft SRL opera EasySign)? | Sí: la norma no regula nombres comerciales; exige identificar siempre a la sociedad, no usar "Entidad de Certificación" y no inducir a error sobre el valor legal. Marca/ONAPI y búsqueda de anterioridad quedan para el abogado (no se hizo). | `docs/INDOTEL_REQUIREMENTS.md` (PR #11) y campo opcional `platformName` en el aviso previo (PR #20) | 9f39b0e, a5a7b01 |

**Consecuencia práctica:** hay que constituir (o usar) una sociedad para las Rutas A y B; los datos legales pendientes son los de esa sociedad.
**Revertir:** `git revert` de cada commit; son cambios de documentación salvo a5a7b01 (campo opcional `platformName`).

## 2026-11-02 (continuación) Estructura legal del operador

- **GetUpSoft es una SRL** (sociedad), registrada a nombre del dueño del producto. Cumple el requisito de persona jurídica de la Ruta A (Res. 067-2025, Anexo II art. 27.1).
- **Su RNC aún no está emitido.** No debe confundirse con el RNC del dueño como persona física. La comunicación al INDOTEL (art. 28) exige RNC, Registro Mercantil vigente y certificación de la DGII de estar al día, por lo que **queda en espera**; no se ha enviado nada ni se ha ofrecido el servicio al público.
- **EasySign y EasyCount no están registrados como marca ni nombre comercial.** Pendiente con el abogado: búsqueda de anterioridad y registro ante la ONAPI; si la marca queda a nombre de la persona física y la opera la SRL, contrato de licencia o cesión.
- **Orden de trámites sugerido (a confirmar con abogado y contador):** RNC de la SRL → Registro Mercantil y nombre comercial vigentes → certificación DGII → registro de marcas → comunicación al INDOTEL dentro de los 30 días desde que se preste el servicio (art. 27.3).
- **Sin dependencia del RNC (pendiente de visto bueno):** PostgreSQL con aislamiento por empresa, OIDC/RBAC, interfaz de OTP y abstracción de proveedores de correo y WhatsApp.
- **Revertir:** documentación solamente.

## 2026-11-02 (continuación) OIDC con roles, aislamiento por empresa y traspaso a la nube

- **Visto bueno del dueño** para empezar PostgreSQL y OIDC. Fase 1 hecha: OIDC (JWKS, emisor, audiencia, algoritmos asimétricos), cuatro roles (`platform_admin`, `tenant_admin`, `tenant_operator`, `auditor`), aislamiento por empresa en registro, consentimientos, auditoría y solicitudes de firma (la solicitud de otra empresa responde 404). Con OIDC activo el token estático queda desactivado salvo `EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN=true`. Rama `feat/easysign-oidc-rbac`, 66/66 pruebas. Detalle en `docs/OIDC_RBAC.md`.
- **Fase 2 (PostgreSQL con RLS) no empezada.** Notas de diseño en `docs/HANDOFF_CLOUD.md`.
- **Traspaso para continuar en la nube:** `docs/HANDOFF_CLOUD.md` y `CLAUDE.md` (palabra clave `RETOMAR EASYSIGN`) en la rama `feat/easysign-oidc-rbac`, que contiene todas las demás ramas.
- **Revertir:** `git revert` de los commits de la rama; solo código nuevo de autenticación y documentación.

## 2026-11-12 PostgreSQL con aislamiento por empresa: primer libro (ES-006)

- **Hecho:** interfaz `LedgerStore` con almacén de archivo/memoria (formato JSONL sin cambios) y `PostgresLedgerStore` (paquete `pg`). Tabla `ledger_events` con `PRIMARY KEY (ledger, seq)`, cadena de hashes conservada y exigida por un disparador, tabla solo de inserción, RLS activado y forzado por `tenant_id` con `app.tenant_id` fijado por transacción, roles `easysign_app` (sin `BYPASSRLS`) y `easysign_auditor` (solo lectura). Migraciones versionadas en `migrations/` con `npm run migrate`; verificación de la cadena completa con `npm run ledger:verify`.
- **Libro migrado:** consentimientos (`consent-ledger.ts`), ahora asíncrono. Se activa con `EASYSIGN_DATABASE_URL`; sin esa variable sigue en archivo o memoria. La API no arranca si el rol de la base puede saltarse el aislamiento.
- **Pruebas:** unitarias siempre; integración contra PostgreSQL 16 real cuando hay `EASYSIGN_TEST_DATABASE_URL` (si no, se saltan). Demuestran que una empresa no lee ni escribe filas de otra ni con SQL directo bajo el rol de la aplicación. Resultado en el ThinkCentre (Node 22, compilación limpia y `npm test`): 74/74 sin base de datos (la suite de PostgreSQL, 8 pruebas, se salta) y 82/82 con un PostgreSQL 16 temporal, que se borró al terminar.
- **Pendiente:** libros de auditoría, registro de certificados y solicitudes de firma (un PR por libro); importador de JSONL existente; documentos. Detalle y límites en `docs/POSTGRES_TENANCY.md`.
- **PR:** #25 contra `feat/easysign-oidc-rbac` (commit ea46cee), sin fusionar.
- **Dependencias nuevas:** `pg` y `@types/pg`.
- **Revertir:** quitar `EASYSIGN_DATABASE_URL` vuelve al archivo sin tocar código; `git revert` de los commits de `feat/easysign-pg-tenant-store`.
