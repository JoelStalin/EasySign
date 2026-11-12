# Correo saliente y código de verificación del firmante

Cubre la parte de correo de ES-013 y un primer control sobre la identidad del firmante. WhatsApp queda solo como interfaz.

## Qué prueba el código y qué no

El código de 6 dígitos se envía al correo del firmante. Quien lo introduce demuestra que en ese momento tenía acceso a ese buzón, además de tener el enlace de firma. **No prueba identidad civil**: no hay cédula, ni biometría, ni comprobación contra un registro oficial. La verificación de identidad (KYC) sigue pendiente y depende de decisiones del dueño. La firma sigue siendo electrónica no cualificada.

## Proveedor de correo

`src/services/mail.ts` define `MailProvider` con dos implementaciones:

| Proveedor | Cuándo | Qué hace |
|---|---|---|
| `NoopMailProvider` | `EASYSIGN_MAIL_PROVIDER=none` o sin definir (por defecto) | No envía. El enlace vuelve al administrador con estado `pending_provider`, igual que antes. |
| `CloudflareEmailProvider` | `EASYSIGN_MAIL_PROVIDER=cloudflare` | Envía por la API REST de Cloudflare Email Sending. |

### Variables

| Variable | Obligatoria con `cloudflare` | Uso |
|---|---|---|
| `EASYSIGN_MAIL_PROVIDER` | — | `cloudflare` o `none`. Otro valor impide arrancar. |
| `EASYSIGN_MAIL_FROM` | Sí | Dirección remitente de un dominio dado de alta en Email Sending, p. ej. `noreply@<dominio>`. |
| `EASYSIGN_MAIL_FROM_NAME` | No | Nombre visible del remitente. También firma los correos si la información previa no trae `platformName`. |
| `CLOUDFLARE_ACCOUNT_ID` | Sí | Cuenta de Cloudflare. |
| `CLOUDFLARE_EMAIL_API_TOKEN` | Sí | Token con permiso **Email Sending: Edit**. Secreto: va en el entorno del servidor, nunca en Git. |
| `EASYSIGN_MAIL_REPLY_TO` | No | Dirección de respuesta. |
| `EASYSIGN_MAIL_API_BASE_URL` | No | Por defecto `https://api.cloudflare.com/client/v4`. Solo admite `https`, salvo `localhost` (pruebas). |

Con `cloudflare` y una variable obligatoria ausente, el servicio no arranca y el error nombra la variable sin mostrar valores.

### Petición a Cloudflare

Confirmado en la documentación oficial el 2026-11-12 ([REST API](https://developers.cloudflare.com/email-service/api/send-emails/rest-api/), [destinatarios](https://developers.cloudflare.com/email-service/examples/email-sending/recipients/)):

```
POST https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send
Authorization: Bearer <token>
Content-Type: application/json

{ "from": { "address": "noreply@dominio", "name": "EasySign" },
  "to": "firmante@correo", "subject": "…", "text": "…", "html": "…" }
```

El remitente con nombre usa la clave **`address`**. La clave `email` es la del *binding* de Workers y la API REST la rechaza; ese error ya rompió el envío en EasyCount. Hay una prueba que falla si reaparece `from.email`.

Respuesta correcta: `{"success": true, "result": {"delivered": [], "queued": [], "permanent_bounces": []}}`. El proveedor trata como error un `success: false` aunque llegue con 200, y un rebote permanente del destinatario.

### Comportamiento ante fallos

- 10 s de espera por intento. Hasta 2 reintentos (300 ms y 600 ms) solo ante error de red, tiempo agotado, 429 o 5xx. Un 4xx no se reintenta.
- Un reintento tras tiempo agotado puede entregar el mismo correo dos veces. Es aceptable: el enlace y el código son los mismos.
- No sigue redirecciones, para que la cabecera `Authorization` no acabe en otro servidor.
- El token nunca se registra ni aparece en un mensaje de error. Si Cloudflare lo devolviera en su respuesta, se sustituye por `[REDACTED]`.
- Si falla el envío del enlace, la entrega queda en `error` y el enlace vuelve al administrador para entregarlo a mano.

### Plantillas

Dos correos en español, con versión de texto y HTML mínimo (párrafos, sin imágenes, tablas ni pie comercial), para que el filtro los trate como transaccionales:

- **Enlace de firma** — asunto `Documento pendiente de firma: <nombre>`.
- **Código de verificación** — asunto fijo, sin el código. El código va solo en el cuerpo.

Los datos que vienen del cliente (nombre, documento) se escapan en el HTML y se limpian de saltos de línea en el asunto.

## Código de verificación (OTP)

### Reglas

| Regla | Valor |
|---|---|
| Formato | 6 dígitos, generados con el generador criptográfico del sistema |
| Usos | Uno. Al verificarse se borra |
| Caducidad | 10 minutos |
| Intentos | 5 por código. Al quinto fallo el código muere, aunque después se escriba el correcto |
| Reenvío | Uno por minuto y cinco por hora por firmante. Un código nuevo invalida el anterior |
| Almacenamiento | Solo HMAC-SHA-256 con sal aleatoria por código, **en memoria** |
| Comparación | Tiempo constante (`timingSafeEqual`) |

El hash no se escribe en ningún libro ni archivo: un espacio de un millón de códigos se recorre sin esfuerzo si alguien obtiene el hash y la sal. Consecuencia: tras un reinicio los códigos pendientes se pierden y el firmante pide otro. La verificación ya hecha sí sobrevive, porque es un evento del libro encadenado. Los límites de reenvío también viven en memoria y se reinician con el proceso.

### Cómo se activa

Por solicitud, al crearla:

```json
POST /v1/signature-workflows
{ "tenantId": "…", "documentName": "…", "documentHash": "…", "requireOtp": true,
  "signers": [{ "name": "Ana", "email": "ana@correo.do", "channel": "link" }] }
```

Sin proveedor de correo real, crear una solicitud con `requireOtp` responde `503 OTP_CHANNEL_NOT_CONFIGURED`, para no dejar firmantes bloqueados. El código va siempre al correo del firmante, aunque el enlace se haya entregado por QR, WhatsApp o a mano.

### Rutas del firmante

Las dos exigen en el cuerpo el token de un solo uso del enlace.

| Ruta | Cuerpo | Respuesta |
|---|---|---|
| `POST /v1/signature-workflows/:id/signers/:signerId/otp/request` | `{token}` | `200 {sent, channel, sentTo, expiresAt}`. `sentTo` va enmascarado (`a***@correo.do`). El código no viaja en la respuesta. |
| `POST /v1/signature-workflows/:id/signers/:signerId/otp/verify` | `{token, code}` | `200` con la vista del firmante y `otpVerified: true`. |

| Error | HTTP | Cuándo |
|---|---|---|
| `OTP_REQUIRED` | 403 | Se intenta firmar sin haber verificado |
| `OTP_INVALID` | 400 | Código incorrecto; incluye `attemptsLeft` |
| `OTP_EXPIRED` | 410 | Pasaron 10 minutos |
| `OTP_TOO_MANY_ATTEMPTS` | 429 | Cinco fallos con ese código |
| `OTP_NO_CODE` | 409 | No hay código activo (nunca pedido, ya usado, o reinicio) |
| `OTP_RESEND_TOO_SOON`, `OTP_RESEND_LIMIT` | 429 | Límite de reenvío; cabecera `Retry-After` |
| `OTP_DELIVERY_FAILED` | 502 | El proveedor falló; el código emitido se anula |
| `OTP_CHANNEL_NOT_CONFIGURED` | 503 | No hay proveedor de correo |
| `INVALID_STATE` | 409 | La solicitud no pide código, o el firmante ya verificó |

El orden para el firmante es: abrir el enlace, abrir el documento, aceptar la información previa, verificar el código, firmar. La página de firma muestra el paso del código después de aceptar y antes del botón Firmar. El servidor impone la regla aunque no se use la página. La verificación vale hasta la firma, también si el administrador reemite el enlace.

### Evidencia

Cada paso queda en dos sitios, siempre **sin el código ni su hash**:

- Libro encadenado de la solicitud (paquete de evidencia): `otp_requested`, `otp_failed`, `otp_verified`, con canal, caducidad, motivo del fallo, IP y agente de usuario. El firmante lleva `otpVerifiedAt`.
- Libro de auditoría: `signer:otp_requested`, `signer:otp_failed`, `signer:otp_verified`, con resultado `success`, `denied` o `error`.

Solo se anotan fallos acotados (hasta cinco códigos incorrectos y una caducidad por código), para que nadie con un enlace pueda inflar el libro.

## WhatsApp

Solo existe la interfaz `MessagingProvider` y `NoopMessagingProvider`. No se envía nada: el canal `whatsapp` sigue devolviendo el enlace con `pending_provider`. Falta que el dueño elija y contrate el proveedor (WhatsApp Business Platform directo o a través de un intermediario) y que las plantillas de mensaje queden aprobadas. El token usado en pruebas anteriores caducó.

## Activar el correo en producción

1. Dar de alta el dominio remitente en Cloudflare, en **Email Service → Email Sending → Onboard Domain**, y esperar a que verifique SPF, DKIM y DMARC. Email Sending exige plan de Workers de pago y DNS en Cloudflare.
2. Crear un token de API con permiso **Email Sending: Edit**. Conviene uno propio de EasySign y no reutilizar el de EasyCount, para poder revocarlo por separado.
3. Cargar en el entorno del servidor, por el mecanismo de despliegue (GitHub Actions): `EASYSIGN_MAIL_PROVIDER=cloudflare`, `EASYSIGN_MAIL_FROM`, `EASYSIGN_MAIL_FROM_NAME`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_EMAIL_API_TOKEN`.
4. Enviar una solicitud de prueba a un buzón propio y revisar que llega a la bandeja principal.

## Límites

- Ningún correo real se ha enviado con este código: las pruebas usan un servidor HTTP falso en `127.0.0.1`. El primer envío real es el paso 4.
- La página de firma con el paso del código se probó por API y se comprobó que el script compila; no se probó en un navegador.
- Los códigos y los límites de reenvío viven en memoria de un solo proceso. Con varias réplicas hará falta un almacén compartido.
- No hay registro de rebotes ni de entregas diferidas más allá de la respuesta inmediata de Cloudflare.

## Pruebas

`src/mail.test.ts` (proveedor contra servidor falso, selección por entorno, plantillas) y `src/signer-otp.test.ts` (servicio, flujo y API). Se ejecutan con `rm -rf dist && npm ci && npm run build && npm test`.

## Revertir

`git revert` de los commits de la rama `feat/easysign-email-otp`. Sin `requireOtp` y con `EASYSIGN_MAIL_PROVIDER` sin definir, el comportamiento es el anterior.
