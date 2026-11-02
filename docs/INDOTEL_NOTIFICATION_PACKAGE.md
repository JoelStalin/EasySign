# Paquete de comunicación al INDOTEL — Proveedor de Servicios de Firma Electrónica

Base: Res. INDOTEL 067-2025, Anexo II arts. 27-33. **No requiere autorización previa** (art. 27.2) pero sí comunicar la información en **30 días** desde que se produce o modifica (art. 27.3); el INDOTEL puede pedir ampliaciones y responder en 15 días (art. 28.2). Este documento prepara el paquete; **no se envía nada sin la confirmación del dueño del producto**.

## Información general (art. 28.1.1)
| Campo | Valor |
|---|---|
| Nombre, dirección, teléfono y correo del solicitante | _por completar_ |
| Representante legal y cédula | _por completar_ |
| RNC | _por completar_ |
| Tipo de servicio | Firma electrónica de documentos (no cualificada): flujo de solicitudes con consentimiento y paquete de evidencia |

## Sociedad comercial nacional (art. 28.1.2)
- [ ] Copia certificada del Certificado de Registro Mercantil vigente (Cámara de Comercio)
- [ ] Certificación de la DGII de estar al día en obligaciones tributarias

## Información técnica (art. 28.1.4)
- [ ] Copia de toda la información que se suministra sobre los servicios: `GET /v1/legal/disclosure`
- [ ] Dirección pública del Registro de certificados: `GET /v1/registry/certificates` (debe publicarse con URL definitiva)
- [ ] Contenido del Registro según el art. 10 num. 2 del Reglamento 335-03 (verificar con abogado)

## Verificaciones previas a publicar el servicio
- [ ] El aviso de que las firmas **no** tienen valor de firma digital aparece en la web, contratos, correos y API (art. 29.1-29.2)
- [ ] No se usa "Entidad de Certificación" en ningún texto (art. 29.3) — `buildServiceDisclosure` lo rechaza
- [ ] Información previa completa en español (art. 33 a-b)
- [ ] Sin publicidad sin consentimiento (art. 33 d) — libro de consentimientos
- [ ] Respuesta a pedidos de información, inspecciones y auditores (art. 33 i-j, 32)
- [ ] Plan de cese con aviso de 90 días (art. 30) — `CESSATION_PLAN.md`
