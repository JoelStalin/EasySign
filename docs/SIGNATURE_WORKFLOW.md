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
- Entrega de enlaces por correo/WhatsApp (ES-013); hoy el administrador recibe los tokens y los entrega.
- Verificación de identidad del firmante (OTP) y fortaleza de la evidencia: hoy el token prueba control del canal donde se entregó, no la identidad civil.
- Sellado criptográfico del documento firmado (PAdES/XAdES básico con el sello de EasySign) y sello de tiempo.
- Los datos personales (nombre y correo) quedan en un log inmutable: definir con el abogado la política de retención y supresión (Ley 172-13) y valorar guardar solo un hash del correo.
- Los tokens de "siguiente firmante" viven en memoria hasta que el administrador los recoge: se pierden si el servicio se reinicia (hay que volver a enviar).
