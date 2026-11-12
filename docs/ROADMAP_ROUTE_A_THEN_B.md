# Hoja de ruta: Ruta A (Proveedor de Servicios de Firma Electrónica) y luego Ruta B (Entidad de Certificación)

Decisión del dueño del producto (2026-11-02): operar primero como **Proveedor de Servicios de Firma Electrónica no cualificado** (Res. INDOTEL 067-2025, Anexo II, cap. III) y construir en paralelo la autorización como **Entidad de Certificación**. Requisitos con artículo en `INDOTEL_REQUIREMENTS.md`.

> Lo que se puede ofrecer en la Ruta A: firma electrónica de contratos y documentos **sin** el valor jurídico de la firma digital. **No** sirve para firmar e-CF ante la DGII (exige certificado de una Entidad de Certificación autorizada). No se debe prometer lo contrario ni usar la expresión "Entidad de Certificación" (art. 29.3).

## Fase A1 — Producto mínimo de firma electrónica (técnico)
| Entrega | Estado |
|---|---|
| Firma XML-DSig real con certificado .p12 (PR #10) | Hecho, sin fusionar |
| Registro público de certificados y revocación (PR #12) | Hecho, sin fusionar |
| Consentimientos y aviso "sin valor de firma digital" (PR #13) | Hecho, sin fusionar |
| Libro de auditoría y evidencia (PR #14) | Hecho, sin fusionar |
| Verificación real y auditoría de firma (PR #15) | Hecho, sin fusionar |
| **Flujo de solicitudes de firma con firmantes, consentimiento y evidencia** | Hecho en este PR |
| Envío de enlaces por correo/WhatsApp (ES-013) | Correo: hecho con Cloudflare Email Sending, apagado por defecto (`docs/EMAIL_AND_OTP.md`). WhatsApp: pendiente, requiere que el dueño contrate proveedor |
| Sellado de documento (PDF/XML firmado con el sello de EasySign, PAdES/XAdES básico) | Pendiente |
| Identidad del firmante (OTP por correo/teléfono) | Pendiente |
| OIDC/RBAC y PostgreSQL con aislamiento por empresa (ES-005/006) | Pendiente (bloque grande) |

## Fase A2 — Puesta en operación como proveedor no cualificado (organizacional)
Ver `INDOTEL_NOTIFICATION_PACKAGE.md`. Resumen: sociedad constituida, Registro Mercantil, certificación DGII de estar al día, comunicar al INDOTEL en 30 días, publicar la información previa al contrato, registro público de certificados y plan de cese (aviso de 90 días).

## Fase B — Entidad de Certificación (en paralelo, largo plazo)
| Paso | Detalle |
|---|---|
| B1 | Constituir la organización y el equipo (personal calificado, art. 36.2 d) |
| B2 | Documentos: Políticas de Certificación (CP/CPS), Manual de Procedimientos, Plan de Seguridad, Plan de Cese, Plan de Contingencia, Política de Datos Personales |
| B3 | Infraestructura PKI: CA raíz offline, CA subordinada, **HSM certificado**, ceremonia de claves, OCSP/CRL firmadas |
| B4 | Identificación presencial o a distancia de nivel alto contra JCE y DGII/RNC (Unidad de Registro propia o contratada) |
| B5 | Cumplimiento ETSI EN 319 401 / 411-1 / 411-2 (y 319 421 si hay sello de tiempo) |
| B6 | Informe de Evaluación de Conformidad por un organismo acreditado (art. 49) y Informe de Pruebas de Seguridad por un ejecutor registrado (art. 50) |
| B7 | Póliza de seguros de responsabilidad (art. 15.3 y Res. 043-2021) |
| B8 | Solicitud de autorización al INDOTEL (Anexo II arts. 12-18); vigencia de 5 años |
| B9 | Después: validar con la DGII el proceso de e-CF con certificados propios (XSD y vectores oficiales) |

## Qué necesita el dueño del producto (no se puede automatizar)
1. Datos legales de la sociedad que operará (razón social, RNC, representante, domicilio en RD).
2. Contratar o designar: abogado especializado, organismo de evaluación de conformidad, ejecutor de pruebas de seguridad, aseguradora, proveedor de HSM, proveedor de correo/WhatsApp.
3. Validar los textos legales (información previa, términos, CP/CPS).
4. Autorizar fusiones a `main` y despliegues (G10, G7).
