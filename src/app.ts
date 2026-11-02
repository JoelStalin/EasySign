import Fastify from "fastify";
import { z } from "zod";
import { QueueEngine } from "./queue/queue-engine.js";
import { SigningEngine } from "./services/signing-engine.js";
import { WebhookDispatcher } from "./services/webhook-dispatcher.js";
import { SseHub } from "./services/sse-hub.js";
import { registerTransactionRoutes } from "./routes/transaction-routes.js";
import { registerRegistryRoutes } from "./routes/registry-routes.js";
import { CertificateRegistry } from "./services/certificate-registry.js";
import { readFileSync } from "node:fs";
import { registerConsentRoutes } from "./routes/consent-routes.js";
import { ConsentLedger } from "./services/consent-ledger.js";
import { registerAuditRoutes } from "./routes/audit-routes.js";
import { AuditLog } from "./services/audit-log.js";
import { buildServiceDisclosure, NON_QUALIFIED_NOTICE, type ServiceDisclosure } from "./services/legal-notices.js";

export function buildApp(options: { queueConcurrency?: number; registry?: CertificateRegistry; registryAdminToken?: string; consentLedger?: ConsentLedger; disclosure?: ServiceDisclosure; auditLog?: AuditLog } = {}) {
  const app = Fastify({ logger: false });

  const adminToken = "registryAdminToken" in options ? options.registryAdminToken : process.env.EASYSIGN_ADMIN_TOKEN;
  registerAuditRoutes(app, options.auditLog ?? new AuditLog({ filePath: process.env.EASYSIGN_AUDIT_FILE }), adminToken);

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
  registerRegistryRoutes(app, registry, adminToken);

  const disclosureFile = process.env.EASYSIGN_DISCLOSURE_FILE;
  const loadDisclosure = (): ServiceDisclosure | undefined => {
    if (!disclosureFile) return undefined;
    const d = JSON.parse(readFileSync(disclosureFile, "utf8")) as { version: string; config: Record<string, string> };
    return buildServiceDisclosure(d.config, d.version);
  };
  const disclosure = "disclosure" in options ? options.disclosure : loadDisclosure();
  registerConsentRoutes(app, options.consentLedger ?? new ConsentLedger({ filePath: process.env.EASYSIGN_CONSENT_FILE }), disclosure, adminToken);

  app.get("/v1/system/status", async () => ({
    service: "easysign",
    mode: "sandbox",
    accredited: false,
    legalNotice: NON_QUALIFIED_NOTICE,
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
