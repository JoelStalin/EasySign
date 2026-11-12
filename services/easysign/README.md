# EasySign

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org)
[![Fastify](https://img.shields.io/badge/Fastify-5.2-black.svg)](https://fastify.dev)
[![DGII Compliance](https://img.shields.io/badge/DGII-Ley%2032--23%20e--CF-blue.svg)](https://dgii.gov.do)
[![High Concurrency](https://img.shields.io/badge/Queue-Priority%20%7C%20Backpressure%20%7C%20SSE-emerald.svg)](docs/HIGH_CONCURRENCY_QUEUE_ARCHITECTURE.md)

Plataforma independiente de servicios de confianza digital y firma electrónica integrada con **EasyCount** y **GetUpSoft**.

Arquitectura de alta concurrencia inspirada en **GetUpPay**. Backend en **Node.js 22 LTS** y **TypeScript** (NodeNext ESM). *FastAPI estrictamente prohibido.*

---

## 🚀 Arquitectura de Alta Concurrencia y Cola de Procesamiento

Para procesar grandes volúmenes de transacciones (emisión masiva de comprobantes fiscales electrónicos e-CF, firmas en lote de documentos y contratos) sin que los usuarios o sistemas externos pierdan comunicación ni experimenten timeouts HTTP (`504 Gateway Timeout`), **EasySign** opera bajo un modelo desacoplado:

1. **Ingestión Asíncrona (< 15 ms):**
   - `POST /v1/transactions/async`: Retorna inmediatamente `HTTP 202 Accepted` con metadatos del trabajo, posición en cola y URLs de seguimiento.
   - `POST /v1/transactions/batch`: Ingesta lotes de hasta **5,000 transacciones** en un único llamado.
2. **Motor de Cola con Prioridad (`QueueEngine`):**
   - Planificación por prioridades: `critical` (firmas inmediatas), `high`, `normal`, `bulk` (lotes nocturnos).
   - Control de concurrencia y backpressure dinámico (`concurrency: 10`, `maxQueueCapacity: 50,000`).
   - Deduplicación idempotente (`Idempotency-Key` + `tenantId`).
   - Reintentos con retroceso exponencial (`baseDelayMs * 2^(intento-1)`) y Dead Letter Queue (DLQ).
3. **Cero Pérdida de Comunicación:**
   - **Server-Sent Events (SSE):** `GET /v1/jobs/:jobId/stream` transmite progreso reactivo en tiempo real al frontend sin necesidad de sondeos pesados.
   - **Sondeo Adaptativo:** `GET /v1/jobs/:jobId` para clientes basados en polling.
   - **Webhooks Asíncronos:** Firma criptográfica HMAC-SHA256 (`X-EasySign-Signature`) enviada al culminar la transacción.
4. **Firma Digital e-CF (DGII Ley 32-23):**
   - Generación de XML-DSig con canonicalización C14N, resumen SHA-256 DigestValue, SignatureValue y código de seguridad de 6 caracteres.

Para el detalle técnico completo y diagramas de secuencia, consulte:
👉 [docs/HIGH_CONCURRENCY_QUEUE_ARCHITECTURE.md](docs/HIGH_CONCURRENCY_QUEUE_ARCHITECTURE.md)

---

## 📦 Cliente TypeScript Oficial (`EasySignClient`)

```typescript
import { EasySignClient } from "easysign";

const client = new EasySignClient({
  baseUrl: "https://easysign.getupsoft.com",
  tenantId: "flai-srl-001",
  apiKey: process.env.EASYSIGN_API_KEY,
});

// 1. Envío asíncrono y espera reactiva
const result = await client.submitAndWait({
  operation: "sign_ecf_xml",
  data: {
    rncEmisor: "131234567",
    eNcf: "E3100000001",
    amountTotal: 25000.0,
  },
  priority: "critical",
  idempotencyKey: "factura-2026-001",
}, {
  onProgress: (percent) => console.log(`Progreso: ${percent}%`),
});

console.log("Comprobante e-CF firmado:", result.signedXml);
console.log("Código de Seguridad DGII:", result.securityCode);
```

---

## 🛠️ Pruebas Automatizadas y Construcción

```bash
# Compilar TypeScript
npm run build

# Ejecutar suite completa de pruebas
npm test
```

### Resultados de Verificación (10/10 PASS):
- `reports sandbox status` ✅
- `does not permit unsigned or unauthenticated signing` ✅
- `EasySignClient: submits async transaction and waits for result with submitAndWait` ✅
- `QueueEngine: processes jobs and handles priority execution` ✅
- `QueueEngine: enforces idempotency with identical key` ✅
- `QueueEngine: retries failed jobs with backoff and sends to DLQ on max retries` ✅
- `QueueEngine: manages batch transactions and aggregate status` ✅
- `API: POST /v1/transactions/async returns 202 Accepted and executes asynchronously` ✅
- `API: POST /v1/transactions/batch handles bulk e-CF signing` ✅
- `API: GET /v1/queue/metrics and Pause/Resume lifecycle` ✅

---

## 📄 Licencia y Autoría

Desarrollado y mantenido por **GetUpSoft** & **EasyCount**.
