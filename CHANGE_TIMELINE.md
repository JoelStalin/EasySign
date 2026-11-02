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
