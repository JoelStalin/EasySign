# Consentimientos y avisos legales

Cubre A-03, A-04, A-05, A-07, A-08 y B-06 de `docs/INDOTEL_REQUIREMENTS.md` (Res. INDOTEL 067-2025, Anexo II arts. 29 y 33; Ley 172-13).

## Aviso de valor jurídico (art. 29.1-29.2)
`NON_QUALIFIED_NOTICE` declara que los certificados y firmas de este proveedor no tienen el valor de firma digital ni de firma digital segura y que no es una Entidad de Certificación autorizada. Aparece en `/v1/system/status` y en `/v1/legal/disclosure`; debe incluirse también en toda UI, contrato y correo.

## Información previa al contrato (art. 33 a-b)
`buildServiceDisclosure(config, version)` exige los diez campos (nombre, RNC, domicilio en RD, descripción, características, límites de responsabilidad, precios, niveles de servicio, obligaciones del suscriptor y canal de reclamos) y rechaza publicar si falta alguno o si se usa la expresión "Entidad de Certificación" (art. 29.3). Incluye la explicación de firma electrónica, digital y digital segura. Se publica en `GET /v1/legal/disclosure`; sin configuración responde 503.

## Libro de consentimientos
Append-only con cadena SHA-256, igual que el registro de certificados. Guarda solo el hash del texto aceptado y su versión, con evidencia (canal, IP, agente). Propósitos: términos del servicio, tratamiento de datos, verificación de identidad y marketing.
- **Marketing: denegado por defecto.** Solo se permite si el último evento de ese propósito es una concesión; ningún otro consentimiento lo implica. Aislado por tenant.
- Retirar un consentimiento sin concesión previa devuelve 409.

## API (escrituras con `Authorization: Bearer <EASYSIGN_ADMIN_TOKEN>`; sin token, 503)
`GET /v1/legal/disclosure` (público) · `POST /v1/consents` · `POST /v1/consents/withdraw` · `GET /v1/consents/:tenantId/:subjectId`

## Configuración
`EASYSIGN_DISCLOSURE_FILE` (JSON `{version, config}`) · `EASYSIGN_CONSENT_FILE` (JSONL) · `EASYSIGN_ADMIN_TOKEN`.

## Pendiente
- Texto legal definitivo revisado por abogado; el contenido de los campos es responsabilidad del operador.
- Interfaz de captura del consentimiento y su versionado por idioma.
- Entrega de datos solo por orden judicial (A-09) y responder consultas de validez (A-10): procedimientos.
