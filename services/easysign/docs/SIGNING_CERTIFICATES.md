# Firma XML-DSig y certificados

`SigningEngine.signEcfXml` firma con **XML-DSig real** (enveloped, C14N 1.0, RSA-SHA256, digest SHA-256) usando una clave privada y un certificado X.509 reales. Antes de este cambio la "firma" era un hash simulado con un certificado inventado.

## Configuración
| Variable | Uso |
|---|---|
| `EASYSIGN_P12_PATH` | Ruta del archivo `.p12`/`.pfx` emitido por un prestador autorizado. |
| `EASYSIGN_P12_PASSPHRASE` | Clave del `.p12`. Nunca se registra en logs ni en mensajes de error. |

No guarde el `.p12` ni su clave en Git (política G6). Entréguelos por el mecanismo de secretos del despliegue.

## Reglas de entorno
- `environment: "production"`: exige certificado real y vigente. Sin certificado, o con el de pruebas, la firma se rechaza con `CERTIFICATE_REQUIRED`.
- `environment: "test"` (predeterminado) sin certificado configurado: usa un certificado autofirmado efímero cuyo titular dice `EasySign TEST - NOT VALID FOR PRODUCTION`. El resultado trae `testCertificate: true` y **no tiene valor legal**.
- Certificado vencido o aún no vigente: `CERTIFICATE_EXPIRED` / `CERTIFICATE_NOT_YET_VALID`.

## Verificación
`verifyEcfXml(signedXml, certificadoEsperadoPem?)` comprueba la firma contra el certificado incrustado en `KeyInfo`, o contra el esperado si se entrega. Cualquier modificación del documento invalida la firma.

## Pendiente (no afirmar cumplimiento DGII)
- Contrastar con la especificación oficial de la DGII: ubicación de la firma, `Reference URI`, transformaciones y la regla exacta del código de seguridad (hoy: primeros 6 caracteres de `SignatureValue`).
- Validar contra el XSD oficial y los vectores de prueba (ES-015). Hasta que pasen no se declara cumplimiento.
- Cadena de confianza, OCSP/CRL y HSM (ES-011).

## Firma de PDF: PAdES-B-B (ES-012)

`SigningEngine.signPdf` ya no es simulada. Firma el PDF con una **firma CMS/PKCS#7 separada (detached)** incrustada en el documento, con `SubFilter` **`ETSI.CAdES.detached`** (perfil PAdES básico, nivel B-B). Usa el mismo almacén de certificados y las mismas reglas de entorno que la firma XML: en producción exige el `.p12` real (`EASYSIGN_P12_PATH` / `EASYSIGN_P12_PASSPHRASE`); fuera de producción, sin certificado configurado, usa el certificado efímero de pruebas y el resultado trae `testCertificate: true`.

Código: `src/services/pdf-signature.ts` (firma y verificación) y `src/services/signing-engine.ts` (`signPdf`, `verifyPdf`). Pruebas: `src/pdf-signature.test.ts`.

### Qué contiene la firma
- CMS `SignedData` con RSA PKCS#1 v1.5 y SHA-256, un solo firmante y su certificado incrustado.
- Atributos firmados: `content-type`, `message-digest` (SHA-256 de los bytes del `ByteRange`) y `signing-certificate-v2` (ata la firma al certificado, requisito de CAdES).
- La **hora de firma** va en la entrada `M` del diccionario de firma del PDF, que queda dentro del `ByteRange` y por tanto firmada. No se usa el atributo CMS `signing-time`: según nuestra lectura del perfil básico de PAdES (ETSI EN 319 142-1) la hora declarada va en `M`. Es la hora del servidor, **no un sello de tiempo**.
- Campo de firma invisible (`EasySignSignature1`), `Reason`, y opcionalmente `Location` y `ContactInfo`. La identidad criptográfica es la del titular del certificado (el sello de la plataforma o de la empresa), no la persona indicada en `signerName`/`signerEmail`: esos datos solo quedan anotados en `Reason`/`ContactInfo`.

### Uso por la cola
- `sign_pdf`: `data = { documentId, tenantId, pdfBase64, signerName, signerEmail, documentHash?, reason?, location?, environment? }`. Si se envía `documentHash` y no coincide con el SHA-256 del PDF recibido, se rechaza.
- Evidencia devuelta: `signedPdfBase64`, `documentHash` (SHA-256 del PDF original), `signedDocumentHash` (SHA-256 del PDF firmado), `byteRangeDigest` (el digest que está dentro de la firma), `byteRange`, `signedAt`, `subFilter`, `profile: "PAdES-B-B"`, `trustedTimestamp: false`, serie, emisor y titular del certificado, y `testCertificate`.
- `verify_signature` con `data = { signedPdfBase64, expectedCertificatePem? }` devuelve `verified`, `errors`, `signingTime` (declarada), `coversWholeDocument`, `documentDigest`, datos del certificado y `validationProfile: "PADES_CRYPTOGRAPHIC_ONLY"`. Con `signedXml` sigue verificando XML-DSig.

### Verificación (`verifyPdfSignature`)
Extrae `ByteRange` y el CMS de `/Contents`; exige que el rango empiece en 0, que el hueco sea exactamente el valor de la firma y que cubra el archivo completo (contenido añadido después de firmar se rechaza); recalcula el digest de los bytes firmados y lo compara con `message-digest`; comprueba `signing-certificate-v2` y el valor de la firma con el certificado incrustado; y, si se entrega `expectedCertificatePem`, exige que sea ese certificado. Cambiar un byte del documento o de la firma invalida el resultado.

También exige que el diccionario de firma sea el valor (`/V`) de un campo de firma (`/FT /Sig`) legible en el archivo; un CMS válido guardado en un objeto que ningún campo referencia no se acepta. Esta comprobación se hace sobre los bytes del archivo, no con un analizador completo de PDF: un PDF firmado por otra herramienta que guarde el campo dentro de un flujo de objetos comprimido se rechaza aunque su firma sea correcta (falla hacia el lado seguro).

Comprobación independiente hecha en el ThinkCentre (2026-11-12): `pdfsig` 24.02 (Poppler) reporta "Signature is Valid" y "Total document signed" sobre un PDF firmado por este motor, y `openssl cms -verify` (OpenSSL 3.0.13) acepta el CMS; esta última corre como prueba automática cuando `openssl` está instalado.

### Límites (no afirmar más de esto)
- **Nivel B-B, no B-T ni B-LT/LTA:** no hay sello de tiempo de una TSA. La hora de firma es la declarada por el servidor.
- **Sin CRL/OCSP incrustados** y sin validación de cadena: la verificación es criptográfica (integridad y firma). No decide si el certificado es de confianza, está vigente ante su emisor o fue revocado; devuelve `trust: "NOT_EVALUATED"`. Solo se incrusta el certificado del firmante, no la cadena intermedia.
- **Ruta A no da valor de firma digital:** una firma PAdES hecha con un certificado que no emitió una Entidad de Certificación autorizada por el INDOTEL es una firma electrónica no cualificada, aunque sea criptográficamente correcta. Con el certificado de pruebas no tiene valor legal alguno.
- No se ha pasado un validador de conformidad ETSI (p. ej. DSS de la Comisión Europea) ni se ha probado en Adobe Acrobat. No se declara conformidad PAdES certificada.
- Una sola firma por documento: el PDF se reescribe al firmar (no es actualización incremental), por lo que un PDF que ya trae una firma se rechaza (`PDF_ALREADY_SIGNED`) en vez de invalidarla. Firmas sucesivas de varios firmantes quedan pendientes. La verificación tampoco admite PDF con varias firmas.
- Solo claves RSA (PKCS#1 v1.5). No RSA-PSS ni ECDSA. PDF cifrados no se firman. Firma invisible, sin apariencia gráfica.
- El PDF viaja en base64 dentro del JSON del trabajo y el límite del cuerpo es el predeterminado de Fastify (1 MB): hoy solo caben PDF de hasta unos 700 KB por esta vía. Falta conectar el motor al flujo de solicitudes de firma (`/v1/signature-workflows`) para sellar el documento subido al completarse.
- La clave privada sigue en un `.p12` en disco/memoria; HSM pendiente (ES-011).
