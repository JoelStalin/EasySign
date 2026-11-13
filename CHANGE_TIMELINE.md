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

## 2026-11-12 Cifrado en reposo de los documentos

- **Qué se hizo:** los documentos de `EASYSIGN_DOCS_DIR` se cifran con AES-256-GCM, una clave por documento envuelta con una KEK (`EASYSIGN_DOCS_KEK`, `EASYSIGN_DOCS_KEK_ID`); las KEK anteriores de `EASYSIGN_DOCS_KEK_PREVIOUS` siguen descifrando. Formato de archivo versionado; la huella sigue siendo la del documento en claro y se comprueba al descifrar. En producción sin KEK el servicio no arranca; en desarrollo sigue sin cifrar con un aviso. Los archivos anteriores sin cifrar siguen legibles y `npm run docs:reencrypt` los cifra y rota la KEK. Rama `feat/easysign-doc-encryption` (base `feat/easysign-oidc-rbac`), 74/74 pruebas. Detalle en `docs/ENCRYPTION_AT_REST.md`.
- **Atención al desplegar:** con `NODE_ENV=production` hay que definir la KEK antes de actualizar, o el servicio no arranca. Si se pierde la KEK, los documentos cifrados con ella no se recuperan.
- **Qué falta:** los libros JSONL (registro, consentimientos, auditoría, solicitudes) guardan datos personales sin cifrar; la política de datos personales (Ley 172-13) y la retención siguen pendientes del abogado; la KEK vive en una variable de entorno, no en un HSM ni KMS; no hay comando para descifrar de vuelta ni revisión criptográfica externa.
- **Revertir:** `git revert` de los commits de la rama. Los archivos ya cifrados no se leen con el código anterior.
## 2026-11-12 Correo por Cloudflare y código de verificación del firmante (ES-013 parcial)

- **Hecho** en la rama `feat/easysign-email-otp` (base `feat/easysign-oidc-rbac`, PR sin fusionar): interfaz `MailProvider` con `CloudflareEmailProvider` (API REST de Email Sending, remitente como `from.address`, tiempos de espera y reintentos acotados, el token nunca se registra) y `NoopMailProvider` (comportamiento anterior: devuelve el enlace). Plantillas en español para el enlace de firma y para el código. Código de un solo uso del firmante, opcional por solicitud (`requireOtp`): 6 dígitos, 10 minutos, 5 intentos, límite de reenvío, solo hash con sal en memoria; sin verificarlo no se puede firmar. Rutas `otp/request` y `otp/verify`, paso nuevo en la página de firma y eventos en el libro de la solicitud y en el de auditoría, sin el código.
- **Pruebas:** `rm -rf dist && npm ci && npm run build && npm test` → 90/90 (66 anteriores + 24 nuevas). El proveedor se prueba contra un servidor HTTP falso local; no se envió ningún correo real ni se usó ningún token real.
- **Límites declarados:** el código prueba control del correo, no identidad civil; KYC sigue pendiente. WhatsApp queda solo como interfaz (`MessagingProvider` sin implementación real). La página de firma con el paso del código no se probó en navegador. Los códigos viven en memoria de un proceso.
- **Pendiente del dueño:** dar de alta el dominio remitente en Cloudflare Email Sending, crear un token con permiso Email Sending: Edit y cargar las variables en el servidor por GitHub Actions; elegir y contratar proveedor de WhatsApp; decidir el proveedor de KYC. Detalle en `docs/EMAIL_AND_OTP.md`.
- **Revertir:** `git revert` de los commits de la rama. Sin `requireOtp` y sin `EASYSIGN_MAIL_PROVIDER`, el comportamiento es el anterior.

- 2026-11-12: correo de EasySign alineado con el servicio compartido de EasyCount (Cloudflare Email Sending, selección automática por credenciales, remitente por defecto noreply@getupsoft.com). Rama feat/easysign-email-otp. Revertir: git revert del commit.
