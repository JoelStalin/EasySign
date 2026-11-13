# Flujo de solicitudes de firma (ES-009) — Ruta A

Firma **electrónica no cualificada**: no tiene el valor jurídico de la firma digital ni de la firma digital segura (Res. 067-2025, Anexo II art. 29.1). Cada respuesta del firmante incluye ese aviso.

## Estados
- Solicitud: `draft → pending → completed | cancelled | expired`.
- Firmante: `waiting → notified → viewed → consented → signed | declined`.

## Reglas
- Orden **secuencial** (por defecto) o **paralelo**. En secuencial solo el primero recibe token al enviar; el siguiente lo recibe cuando el anterior firma.
- Token de un solo uso por firmante, de 256 bits: solo se guarda su SHA-256 (nunca en claro, ni en el log ni en la auditoría). Cinco intentos fallidos bloquean al firmante (429).
- Para firmar hay que: **ver** el documento, **aceptar** la información previa vigente (se compara su hash y se registra en el libro de consentimientos) y **confirmar el hash del documento** (SHA-256). Si el hash no coincide, se rechaza.
- Vencimiento configurable (1 a 720 horas, 168 por defecto). Si un firmante rechaza, la solicitud se cancela.
- No se puede enviar si la información previa al contrato (`/v1/legal/disclosure`) no está publicada (503).
- Un anónimo no puede saber qué solicitudes existen: los ids desconocidos responden igual que un token inválido.

## API
Administrador (Bearer `EASYSIGN_ADMIN_TOKEN`; sin token, 503): `POST /v1/signature-workflows`, `POST .../:id/send` (devuelve los tokens para entregarlos), `POST .../:id/next-tokens`, `POST .../:id/cancel`, `GET .../:id`, `GET .../:id/evidence`.
Firmante (token en el cuerpo): `POST /v1/signature-workflows/:id/signers/:signerId/{view,consent,sign,decline}`. El firmante ve solo su propio estado, nunca los correos de los demás.

## Evidencia
`GET .../:id/evidence` devuelve eventos en orden con su hash, el hash del documento, el estado final, `chainValid`, el hash de cabeza del libro y un `packageHash`. Es evidencia de firma electrónica; no la convierte en firma digital.

## Configuración
`EASYSIGN_WORKFLOW_FILE` (JSONL; sin él, solo memoria), además de `EASYSIGN_ADMIN_TOKEN`, `EASYSIGN_DISCLOSURE_FILE`, `EASYSIGN_CONSENT_FILE`, `EASYSIGN_AUDIT_FILE`.

## Pendiente
- Entrega de enlaces por WhatsApp (ES-013): sin proveedor; el administrador recibe los tokens y los entrega. El correo ya tiene proveedor opcional (Cloudflare) y código de verificación del firmante: ver `docs/EMAIL_AND_OTP.md`.
- Verificación de identidad del firmante (OTP) y fortaleza de la evidencia: hoy el token prueba control del canal donde se entregó, no la identidad civil.
- Sellado criptográfico del documento firmado (PAdES/XAdES básico con el sello de EasySign) y sello de tiempo.
- Los datos personales (nombre y correo) quedan en un log inmutable: definir con el abogado la política de retención y supresión (Ley 172-13) y valorar guardar solo un hash del correo.
- Los tokens de "siguiente firmante" viven en memoria hasta que el administrador los recoge: se pierden si el servicio se reinicia (hay que volver a enviar).

## Entrega del enlace: el cliente elige el canal (y puede ser un QR en pantalla)
Cada firmante lleva su canal (`channel`): `email`, `whatsapp`, `link` o `qr`. Se elige al crear la solicitud y se puede **cambiar después** con `POST /v1/signature-workflows/:id/signers/:signerId/reissue {channel}` (por ejemplo, de correo a QR si el firmante está presente).
- **qr:** la respuesta trae `qrSvg` (SVG generado en el servidor, sin servicios externos) y `signingUrl`. El cliente lo muestra en pantalla y el firmante lo escanea con su teléfono.
- **link:** `signingUrl` para copiar y entregar.
- **email / whatsapp:** se envían por el proveedor configurado (ES-013). **Sin proveedor no se envía nada**: el resultado es `pending_provider` e incluye el enlace para entregarlo a mano. WhatsApp exige teléfono en formato internacional (`+18095550100`). Si el proveedor envía, el enlace no se devuelve en la respuesta.
- **El token va en el fragmento del enlace** (`/sign/<solicitud>/<firmante>#<token>`): los navegadores no lo envían al servidor ni queda en los logs de acceso; la página lo lee y lo borra de la barra de direcciones.
- **Reemisión:** invalida el token anterior, desbloquea al firmante tras 5 fallos y cubre el caso de reinicio del servicio. Solo para firmantes que ya tienen su turno.

### Página de firma (`GET /sign/:solicitud/:firmante`)
Estática y sin secretos. Muestra el aviso de que no tiene valor de firma digital, el documento (nombre y huella SHA-256) y la información previa; exige marcar la aceptación y luego Firmar o Rechazar. Cabeceras: CSP `script-src 'self'`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Todo texto del API se inserta con `textContent` (nunca `innerHTML`). Verificada en un navegador real: flujo completo `created → sent → viewed → consented → signed → completed`.

### Configuración adicional
`EASYSIGN_PUBLIC_BASE_URL` (origen público para construir los enlaces; sin él el envío devuelve `error`).

### Límites declarados
- La página muestra la **huella** del documento pero aún no el documento: falta un visor/descarga del documento antes de firmar (pendiente, importante para la solidez de la evidencia).
- Quien escanea el QR (o abre el enlace) puede firmar: el token prueba posesión del enlace, no identidad civil. Para QR en pantalla, el cliente debe asegurarse de que lo escanea el firmante correcto; el OTP de identidad sigue pendiente.
- Los proveedores de correo y WhatsApp no están integrados.

## Visor del documento: el firmante ve lo que firma
- **Subida (administrador):** `PUT /v1/signature-workflows/:id/document` con el archivo como cuerpo (`application/pdf`, `image/png`, `image/jpeg` o `text/plain`) y, opcional, `X-File-Name`. El servidor **calcula el SHA-256 del archivo y lo compara con el `documentHash` de la solicitud** (si no coincide, 409). Solo se acepta mientras la solicitud es un borrador. Máximo 10 MB.
- **El tipo lo decide el contenido, no el cliente:** se reconoce por los bytes (PDF, PNG, JPEG o texto UTF-8 sin bytes nulos). Ejecutables y binarios se rechazan (400). El nombre de archivo se sanea.
- **Almacén por huella:** el archivo se guarda con su SHA-256 como nombre (`EASYSIGN_DOCS_DIR`; sin él, solo memoria). Al leerlo se recalcula el hash: si el archivo se alteró en disco, no se entrega.
- **Sin documento no se envía:** `POST .../send` responde 409 `DOCUMENT_REQUIRED` salvo que el administrador confirme con `{"acknowledgeNoDocument": true}` que el firmante no podrá abrirlo en la plataforma (entonces la página le pide comparar la huella).
- **El firmante debe abrirlo:** `POST .../signers/:signerId/document {token}` entrega el archivo y registra el evento `document_viewed` (una vez, con fecha). Sin abrirlo, el servidor rechaza aceptar los términos y firmar (409), y la página no muestra esos pasos. La evidencia incluye `documentViewedAt` por firmante.
- **Entrega segura:** `Content-Type` real, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` y `Content-Security-Policy: sandbox; default-src 'none'`. En la página, texto se muestra con `textContent`, imágenes con una URL local (`blob:`) y PDF se abre en otra pestaña o se descarga.
- **Auditoría:** las subidas quedan auditadas sin guardar el contenido.

Probado de extremo a extremo en un navegador real: `created → document_attached → sent → viewed → document_viewed → consented → signed → completed`.

### Límites
- Abrir el documento prueba que se entregó al navegador del firmante, no que lo leyó.
- No hay visor de PDF incrustado (se abre en otra pestaña del navegador).
- Documentos grandes o confidenciales: se cifran en reposo cuando hay `EASYSIGN_DOCS_KEK` (obligatoria en producción; ver `docs/ENCRYPTION_AT_REST.md`). La retención sigue por definir con el abogado.
