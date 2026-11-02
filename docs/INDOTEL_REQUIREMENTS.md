# Requisitos INDOTEL / DGII — matriz de trazabilidad

Fuente primaria: [Resolución INDOTEL 067-2025](https://indotel.gob.do/wp-content/uploads/2025/08/Res._067-2025_Contiene_la_Norma_sobre_Servicios_de_Confianza_y_Norma_de_procedimiento_de_acreditacion_y_autorizacion_signed.pdf) (3-jul-2025, 93 págs.): Anexo I (Norma sobre Servicios de Confianza y Certificación Digital) y Anexo II (Procedimientos de Autorización y Acreditación). Marco: Ley 126-02, Decreto 335-03 (Reglamento de Aplicación), Ley 32-23 y normas e-CF de la DGII.

> Este documento es un análisis técnico, no una certificación ni un dictamen legal. Debe validarlo un abogado especializado y, para la autorización, el organismo de evaluación de conformidad. Aún no se han leído en detalle: arts. 49-50 del Anexo I (evaluación y pruebas de seguridad), arts. 66-69 del Reglamento 335-03, ni la especificación técnica de la DGII para firma de e-CF.

## 1. Hallazgo central: hay tres figuras distintas

| Figura | Autorización INDOTEL | Valor jurídico de lo que emite | Norma |
|---|---|---|---|
| **Proveedor de Servicios de Firma Electrónica** (no cualificado) | No requiere autorización previa; solo comunicar información en 30 días | Sus certificados **no** tienen el valor de firma digital ni de firma digital segura (Anexo II art. 29.1); no puede usar la expresión "Entidad de Certificación" (29.3) | Anexo II arts. 27-33 |
| **Entidad de Certificación** (cualificada) | **Sí**, autorización expresa, por 5 años, solo para los servicios autorizados | Certificados cualificados: valor de firma digital / firma digital segura | Anexo II arts. 12-18; Anexo I arts. 35-36, 49-50 |
| **Unidad de Registro** | Sí (autorización propia) | Verifica identidad del solicitante para una Entidad de Certificación | Anexo II arts. 19-26 |

**Consecuencia para DGII:** la DGII exige que el e-CF se firme con un certificado emitido por una entidad autorizada por INDOTEL. Un Proveedor no cualificado **no** sirve para firmar e-CF ante la DGII. Para eso hace falta ser Entidad de Certificación (o emitir a través de una).

### ¿Puede una persona física ser proveedora?
| Figura | ¿Persona física? | Fuente (Res. 067-2025) |
|---|---|---|
| Entidad de Certificación | **No.** Institución o persona jurídica, constituida en RD o en el extranjero, con domicilio legal en RD | Anexo II art. 12.1 |
| Proveedor de Servicios de Firma Electrónica (no cualificado) | **No.** "Personas jurídicas, nacionales o extranjeras, públicas o privadas" | Anexo II art. 27.1 |
| Unidad de Registro | **Sí.** "Persona física o jurídica, nacional o extranjera" (con autorización del INDOTEL) | Anexo II art. 19.1 |

Consecuencia: para operar la Ruta A o la Ruta B hace falta una **sociedad** (la comunicación del proveedor incluye Registro Mercantil y certificación de la DGII de estar al día, Anexo II art. 28.1.2). Una persona física solo puede aspirar a ser **Unidad de Registro** (verificar identidad de solicitantes para una Entidad de Certificación), y aun así con autorización. Puede, por supuesto, ser **suscriptora** (titular de un certificado) o usuaria. Pendiente de confirmar con el abogado: Ley 126-02 y Reglamento 335-03 (arts. 66-67), que no se han leído en detalle y podrían añadir condiciones.

## 2. Ruta A — Proveedor de Servicios de Firma Electrónica (Anexo II, cap. III)

| Req. | Obligación | Estado en EasySign |
|---|---|---|
| A-01 (27.3, 28) | Comunicar al INDOTEL datos del proveedor (RNC, representante, Registro Mercantil, certificación DGII al día, tipo de servicio) en 30 días | Trámite organizacional |
| A-02 (28.1.4 b, 31) | Registro público de certificados, siempre disponible, con estado (emitido, suspendido, revocado, reactivado) | **Pendiente** (ES-011) |
| A-03 (29.1-29.2) | Declarar en toda comunicación que sus certificados no tienen valor de firma digital | **Pendiente** (textos UI/API) |
| A-04 (29.3) | No usar "Entidad de Certificación" | Aplicar en marca y textos |
| A-05 (33 a-b) | Informar en español claro: diferencias firma electrónica/digital/digital segura, características, límites de responsabilidad, precios, SLA, obligaciones del suscriptor, domicilio, canal de reclamos | **Pendiente** |
| A-06 (33 c) | Cumplir el SLA pactado | ES-018 |
| A-07 (33 d) | Sin publicidad al suscriptor sin consentimiento | **Pendiente** (consentimiento) |
| A-08 (33 e, Ley 172-13) | Protección de datos personales | **Pendiente** (DPIA) |
| A-09 (33 f) | Entregar datos solo por sentencia firme o autorización judicial | Procedimiento legal |
| A-10 (33 g-h) | Mantener registros actualizados y responder consultas de validez/alcance | **Pendiente** |
| A-11 (33 i-j, 32) | Proveer información al INDOTEL; permitir auditores e inspectores | Procedimiento + evidencia |
| A-12 (30) | Aviso de cese con 90 días de anticipación | Plan de cese |

## 3. Ruta B — Entidad de Certificación (cualificada)

Contenido mínimo de la solicitud (Anexo II art. 14.1.7): Políticas de Certificación, Manual de Procedimientos, Plan de Seguridad, Plan de Cese, Plan de Contingencia, Política de Protección de Datos Personales, **Informe de Evaluación de Conformidad** (art. 49) e **Informe de Pruebas de Seguridad** (art. 50). Además: personería jurídica, Registro Mercantil, certificación DGII al día, domicilio en RD y **póliza de seguros** (art. 15.3). El INDOTEL puede inspeccionar (art. 52).

| Req. | Obligación (Anexo I art. 35-36) | Estado |
|---|---|---|
| B-01 (35.1) | Prácticas equivalentes a ETSI EN 319 401, 319 411-1 y 319 411-2 (certificados); ETSI EN 319 421 y EN 319 422 (sellos de tiempo) | **Pendiente** |
| B-02 (35.4) | Validación de firmas: ETSI EN 319 102-1 y TS 119 102-2. Formatos: XAdES (TS 319 132), CAdES (TS 319 122), PAdES (TS 319 142) | Parcial: XML-DSig básico (PR #10); XAdES pendiente |
| B-03 (36.2 a-c) | Verificar identidad contra JCE (personas) y DGII/RNC (jurídicas); a distancia, método de identificación electrónica de **nivel alto** | **Pendiente** (ES-014) |
| B-04 (36.2 d) | Personal calificado y capacitado en seguridad y datos personales | Organizacional |
| B-05 (36.2 e) | Recursos financieros y póliza de responsabilidad civil | Organizacional |
| B-06 (36.2 f) | Informar condiciones de uso antes del contrato | **Pendiente** |
| B-07 (36.2 g-i) | Sistemas fiables contra alteración; almacenamiento verificable; medidas contra falsificación y robo de datos | **Pendiente** (HSM, hardening) |
| B-08 (36.2 j) | Conservar registros pertinentes aun tras el cese, como prueba legal | **Pendiente** (libro de evidencia inmutable) |
| B-09 (36.2 k) | Plan de cese actualizado | Documento |
| B-10 (36.2 m-n) | Repositorio de certificados al día; **publicar revocación en máximo 24 h**, efectiva al publicar | **Pendiente** |
| B-11 (36.3) | Estado de validez/revocación siempre disponible, también tras expirar, automatizado, fiable y **gratuito** (OCSP/CRL) | **Pendiente** |
| B-12 (27) | Dispositivo cualificado de creación de firma (HSM certificado) | **Pendiente** |
| B-13 (Anexo II 26) | Autorización por 5 años y renovación | Calendario |
| B-14 (18) | Inscripción en la Lista de Servicios de Confianza | Trámite |

## 4. Ruta DGII (e-CF)

| Req. | Obligación | Estado |
|---|---|---|
| D-01 | El e-CF se firma con certificado de una entidad autorizada por INDOTEL | Dependiente de la Ruta B (o de una EC aliada) |
| D-02 | XML firmado válido contra XSD oficial, con firma verificable | **Parcial** (XML-DSig real en PR #10; XSD y vectores pendientes) |
| D-03 | Aprobación del proceso de certificación de emisor en el portal DGII | Por emisor |
| D-04 | Código de seguridad: confirmar regla exacta con la especificación oficial | **Por verificar** (hoy: 6 primeros caracteres de SignatureValue) |

## 5. Decisión requerida (la toma el dueño del producto)

1. **Ruta A primero:** operar ya como Proveedor de Servicios de Firma Electrónica (firma de contratos/documentos, sin valor de firma digital), y construir en paralelo la Ruta B.
2. **Ruta B directa:** ir a Entidad de Certificación (la única que sirve para e-CF ante la DGII), con inversión previa en HSM, auditoría de conformidad ETSI, pruebas de seguridad, póliza y organización.
3. **Alianza:** usar una Entidad de Certificación ya autorizada como emisora y que EasySign sea plataforma de firma y Unidad de Registro/proveedor.

Nada de lo anterior debe declararse como cumplido ni ofrecerse como "firma digital válida" hasta tener la autorización o el acuerdo correspondiente.
