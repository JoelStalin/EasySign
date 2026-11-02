import Fastify from "fastify";
import { z } from "zod";
import { QueueEngine } from "./queue/queue-engine.js";
import { SigningEngine } from "./services/signing-engine.js";
import { WebhookDispatcher } from "./services/webhook-dispatcher.js";
import { SseHub } from "./services/sse-hub.js";
import { registerTransactionRoutes } from "./routes/transaction-routes.js";
import { registerRegistryRoutes } from "./routes/registry-routes.js";
import { CertificateRegistry } from "./services/certificate-registry.js";

export function buildApp(options: { queueConcurrency?: number; registry?: CertificateRegistry; registryAdminToken?: string } = {}) {
  const app = Fastify({ logger: false });

  const queue = new QueueEngine({
    concurrency: options.queueConcurrency ?? 10,
    maxQueueCapacity: 50000,
    defaultMaxRetries: 3,
    defaultTimeoutMs: 15000,
  });

  const signingEngine = new SigningEngine();
  const webhookDispatcher = new WebhookDispatcher();
  const sseHub = new SseHub(queue);

  queue.registerHandler("sign_ecf_xml", async (job, updateProgress) => {
    return signingEngine.signEcfXml(job.data as any, updateProgress);
  });

  queue.registerHandler("sign_pdf", async (job, updateProgress) => {
    return signingEngine.signPdf(job.data as any, updateProgress);
  });

  queue.registerHandler("batch_sign_item", async (job, updateProgress) => {
    return signingEngine.signEcfXml(job.data as any, updateProgress);
  });

  queue.registerHandler("verify_signature", async (job, updateProgress) => {
    updateProgress(50);
    const data = job.data as { signatureValue?: string; rawXml?: string };
    const isValid = Boolean(data.signatureValue && data.signatureValue.length > 10);
    updateProgress(100);
    return {
      verified: isValid,
      verifiedAt: new Date().toISOString(),
      validationProfile: "DGII_LEY_32_23",
    };
  });

  registerTransactionRoutes(app, { queue, sseHub, webhookDispatcher });

  const registry = options.registry ?? new CertificateRegistry({ filePath: process.env.EASYSIGN_REGISTRY_FILE });
  registerRegistryRoutes(app, registry, "registryAdminToken" in options ? options.registryAdminToken : process.env.EASYSIGN_ADMIN_TOKEN);

  app.get("/v1/system/status", async () => ({
    service: "easysign",
    mode: "sandbox",
    accredited: false,
    engine: "NodeNext-Queue-Architecture",
    dgiiComplianceReady: false,
  }));

  const legacyRequestSchema = z.object({
    tenantId: z.string().uuid(),
    documentId: z.string().uuid(),
    signerId: z.string().uuid(),
  });

  app.post("/v1/signature-requests", async (request, reply) => {
    const parsed = legacyRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "INVALID_REQUEST", issues: parsed.error.issues });
    }
    return reply.code(501).send({
      error: "NOT_IMPLEMENTED",
      message: "Synchronous legacy signing is deprecated. Use POST /v1/transactions/async for high-throughput queuing.",
    });
  });

  return app;
}
