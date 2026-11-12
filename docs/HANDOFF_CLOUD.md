# EasySign — traspaso para continuar en la nube

> Palabra clave del dueño del producto: **`RETOMAR EASYSIGN`**. Quien la reciba debe leer este documento, resumir el estado en pocas líneas y seguir en "Siguiente paso".
> Fecha del traspaso: 2026-11-02. Rama con todo el trabajo: **`feat/easysign-oidc-rbac`** (contiene todas las demás ramas de código y de documentación).

## 1. Qué es EasySign
Plataforma de firma electrónica (Node 22, TypeScript NodeNext, Fastify 5, Zod). **FastAPI está prohibido.** Pensada para operar primero como **Proveedor de Servicios de Firma Electrónica no cualificado (Ruta A)** y construir en paralelo la autorización como **Entidad de Certificación (Ruta B)**, según la Res. INDOTEL 067-2025. Ver `docs/ROADMAP_ROUTE_A_THEN_B.md` y `docs/INDOTEL_REQUIREMENTS.md`.

## 2. Decisiones del dueño del producto (no reabrir sin preguntar)
- **Ruta A y luego B.** La Ruta A da firma electrónica **sin** valor de firma digital y **no sirve para firmar e-CF ante la DGII** (eso exige un certificado de una Entidad de Certificación autorizada por el INDOTEL).
- **Persona jurídica obligatoria:** ni la Entidad de Certificación (Anexo II art. 12.1) ni el Proveedor de Servicios de Firma Electrónica (art. 27.1) pueden ser personas físicas; la Unidad de Registro sí (art. 19.1).
- **Operador:** GetUpSoft **SRL**, registrada a nombre del dueño. **Su RNC aún no está emitido** (no confundir con el RNC del dueño como persona física). Sin RNC, Registro Mercantil vigente y certificación de la DGII **no se puede completar la comunicación al INDOTEL** (Anexo II art. 28). No se ha enviado nada a ningún organismo y **no debe enviarse sin confirmación expresa del dueño**.
- **Marca:** la plataforma puede llamarse distinto de la sociedad ("EasySign" operada por GetUpSoft SRL). `EasySign` y `EasyCount` **no están registradas** como marca ni nombre comercial; falta búsqueda de anterioridad y registro ante la ONAPI (abogado).
- **Entrega del enlace de firma:** la elige el cliente por firmante (`email`, `whatsapp`, `link`, `qr`) y puede ser un **QR en pantalla**.
- **Nunca afirmar** cumplimiento con la DGII ni valor de firma digital. `dgiiComplianceReady` es `false` a propósito.

## 3. Reglas de trabajo del dueño (gobierno del repositorio)
- Todo cambio, por pequeño que sea, va en **su propia rama**; **nunca** commits en `main` ni `dev`. **Cada commit se sube de inmediato.**
- `main` solo por PR y **solo el dueño autoriza fusionar**. Despliegues de producción solo por GitHub Actions.
- Sin secretos en Git (el `.p12` y su clave se entregan por variables de entorno/secretos).
- Nada se envía a la DGII ni al INDOTEL sin confirmación del dueño. Operaciones destructivas piden confirmación.
- El código se escribe en el ThinkCentre (Linux) y se hace pull para probar; en la nube, trabajar sobre una rama nueva desde `feat/easysign-oidc-rbac`.
- Mensajes de commit terminan con `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; descripciones de PR con `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- Responder al dueño **en español**.

## 4. Estado del código (cadena de PR en JoelStalin/EasySign, ninguno fusionado)
| PR | Rama | Qué aporta |
|---|---|---|
| #10 | `feat/easysign-xmldsig-signing-engine-hardening` | Firma XML-DSig real con certificados .p12 (antes era un hash simulado) |
| #11 | `docs/easysign-indotel-requirements-matrix` | Matriz de requisitos INDOTEL/DGII, persona jurídica y nombre de marca |
| #12 | `feat/easysign-certificate-registry-revocation` | Registro público de certificados y revocación (log encadenado, SLA 24 h) |
| #13 | `feat/easysign-consent-legal-notices` | Libro de consentimientos y avisos legales |
| #14 | `feat/easysign-audit-evidence-ledger` | Libro de auditoría y evidencia con id de correlación |
| #15 | `feat/easysign-verify-and-sign-audit` | `verify_signature` real y auditoría de firma |
| #16 | `feat/easysign-signature-workflow` | Flujo de solicitudes de firma, plan A→B, paquete INDOTEL, plan de cese |
| #17 | `feat/easysign-delivery-qr` | Canal por firmante y QR en pantalla; página de firma |
| #18 | `feat/easysign-document-viewer` | Subida y visor del documento; el firmante debe abrirlo antes de firmar |
| #19 | `docs/easysign-change-timeline` | `CHANGE_TIMELINE.md` |
| #20 | `feat/easysign-platform-name` | Campo opcional `platformName` en el aviso previo |
| (nuevo) | `feat/easysign-oidc-rbac` | **OIDC + roles + aislamiento por empresa** (este traspaso va en esta rama) |
| #26 | `feat/easysign-pades-signing` | **Firma PAdES-B-B real de PDF y `verifyPdfSignature`** (ES-012; base `feat/easysign-oidc-rbac`, sin fusionar). 75 pruebas en esa rama. Límites en `docs/SIGNING_CERTIFICATES.md` |

Orden de fusión sugerido (solo con autorización): #10, #11, #12, #13, #14, #15, #16, #17, #18, #19, #20 y luego el de OIDC. `feat/easysign-oidc-rbac` ya contiene las demás ramas (también las de documentación) para trabajar en un único sitio.

## 5. Cómo probar
```bash
git clone git@github.com:JoelStalin/EasySign.git && cd EasySign
git checkout feat/easysign-oidc-rbac
npm ci && rm -rf dist && npm run build && npm test   # 66 pruebas, ~1 min (la de estrés es lenta)
```
Node ≥ 22. Si cambia de rama, **borre `dist/`** antes de `npm test` (está ignorado y arrastra pruebas viejas).

## 6. Variables de entorno (ninguna lleva secretos en el repositorio)
`EASYSIGN_PUBLIC_BASE_URL` (origen para los enlaces de firma) · `EASYSIGN_P12_PATH`, `EASYSIGN_P12_PASSPHRASE` (certificado real; en producción es obligatorio) · `EASYSIGN_REGISTRY_FILE`, `EASYSIGN_CONSENT_FILE`, `EASYSIGN_AUDIT_FILE`, `EASYSIGN_WORKFLOW_FILE` (JSONL; sin ellos, memoria) · `EASYSIGN_DOCS_DIR` (documentos) · `EASYSIGN_DISCLOSURE_FILE` (JSON `{version, config}` con la información previa) · `EASYSIGN_ADMIN_TOKEN` (token estático, provisional) · `EASYSIGN_OIDC_ISSUER`, `EASYSIGN_OIDC_AUDIENCE`, `EASYSIGN_OIDC_JWKS_URI`, `EASYSIGN_OIDC_ROLES_CLAIM`, `EASYSIGN_OIDC_TENANT_CLAIM`, `EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN`. Detalle en `docs/OIDC_RBAC.md`.

## 7. Siguiente paso (el dueño ya dio el visto bueno: "Sí, empieza")
**Fase 2 — PostgreSQL con aislamiento por empresa (ES-006).** No empezada. Notas de diseño:
- Hoy los cuatro libros (`certificate-registry`, `consent-ledger`, `audit-log`, `signature-workflow`) son **event-sourced en memoria con un JSONL encadenado por SHA-256** y son **síncronos**. Los documentos están en `document-store` (archivos por huella).
- Propuesta: interfaz `LedgerStore` con implementación de archivo (la actual) y PostgreSQL; tabla de eventos `(ledger, seq, tenant_id, type, at, payload jsonb, prev_hash, hash)` con `PRIMARY KEY (ledger, seq)`, **conservar la cadena de hashes** y verificar al arrancar; **RLS por `tenant_id`** (`SET LOCAL app.tenant_id` por transacción) y rol de aplicación sin `BYPASSRLS`; migraciones versionadas; documentos en almacenamiento de objetos o `bytea` con hash.
- Requiere volver los servicios **asíncronos** (los llamantes y las pruebas hoy son síncronos). Hacerlo por libro, un PR por libro, empezando por el más simple (consentimientos).
- Probar con un PostgreSQL temporal (contenedor `postgres:16` en puerto aleatorio) y **demostrar el aislamiento con pruebas** (un tenant no lee ni escribe filas de otro, ni siquiera con SQL directo bajo el rol de la app).
- Después: OTP de identidad del firmante y proveedores de correo/WhatsApp (el dueño debe elegir/contratar), conectar el motor PAdES (PR #26) al flujo de solicitudes para sellar el documento al completarse, sello de tiempo (elegir TSA), XAdES, CRL/OCSP firmadas (requiere clave de CA, Ruta B).

## 8. Pendiente que depende del dueño
RNC de la SRL (comunicación al INDOTEL) · proveedores de correo y WhatsApp · abogado, organismo de evaluación de conformidad, aseguradora y proveedor de HSM para la Ruta B · registro de marcas · autorizar fusiones a `main`.

## 9. Límites declarados (no ocultar)
Identidad del firmante: el enlace/QR prueba posesión, no identidad civil · correo/WhatsApp no envían (devuelven el enlace) · documentos sin cifrar en reposo · datos personales en logs inmutables (política Ley 172-13 por definir) · sin leer aún: Ley 126-02 y Reglamento 335-03 (arts. 66-67), que podrían añadir condiciones · no se hizo búsqueda de anterioridad de marca · los tokens del "siguiente firmante" viven en memoria (usar `/reissue` tras un reinicio).

## 10. Fuente regulatoria
Res. INDOTEL 067-2025 (PDF oficial): https://indotel.gob.do/wp-content/uploads/2025/08/Res._067-2025_Contiene_la_Norma_sobre_Servicios_de_Confianza_y_Norma_de_procedimiento_de_acreditacion_y_autorizacion_signed.pdf — Anexo I (norma de servicios de confianza) y Anexo II (autorización y acreditación). Los artículos clave están resumidos en `docs/INDOTEL_REQUIREMENTS.md`.

## 11. Cómo revertir
Cada PR se revierte con `git revert <commit>`; los commits están en `CHANGE_TIMELINE.md`. Nada se ha fusionado a `main`, así que basta con cerrar los PR sin fusionar.
