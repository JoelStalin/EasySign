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
import pg from "pg";
import { CONSENT_LEDGER, ConsentLedger } from "./services/consent-ledger.js";
import { PostgresLedgerStore } from "./storage/postgres-ledger-store.js";
import type { LedgerDefinition } from "./storage/ledger-store.js";
import { registerAuditRoutes } from "./routes/audit-routes.js";
import { AUDIT_LEDGER, AuditLog } from "./services/audit-log.js";
import { Guard, authenticatorFromEnv, type Authenticator } from "./auth/guard.js";
import { registerWorkflowRoutes } from "./routes/workflow-routes.js";
import { SignatureWorkflow } from "./services/signature-workflow.js";
import { registerSignPage } from "./routes/sign-page.js";
import type { DeliveryProvider } from "./services/delivery.js";
import { DocumentStore } from "./services/document-store.js";
import { buildServiceDisclosure, NON_QUALIFIED_NOTICE, type ServiceDisclosure } from "./services/legal-notices.js";

export function buildApp(options: { queueConcurrency?: number; registry?: CertificateRegistry; registryAdminToken?: string; consentLedger?: ConsentLedger; databaseUrl?: string; disclosure?: ServiceDisclosure; auditLog?: AuditLog; workflow?: SignatureWorkflow; authenticator?: Authenticator; publicBaseUrl?: string; deliveryProviders?: DeliveryProvider[]; documents?: DocumentStore } = {}) {
  const app = Fastify({ logger: false });

  const staticAdminToken = "registryAdminToken" in options ? options.registryAdminToken : process.env.EASYSIGN_ADMIN_TOKEN;
  const guard = new Guard("authenticator" in options ? options.authenticator : authenticatorFromEnv(process.env, staticAdminToken));
  // With EASYSIGN_DATABASE_URL the consent and audit ledgers live in PostgreSQL under per-tenant row level security
  // (docs/POSTGRES_TENANCY.md); without it, in JSONL files or in memory as before.
  const databaseUrl = "databaseUrl" in options ? options.databaseUrl : process.env.EASYSIGN_DATABASE_URL;
  let pool: pg.Pool | undefined;
  const postgresStore = <P>(definition: LedgerDefinition<P>): PostgresLedgerStore<P> => {
    if (!pool) {
      const created = new pg.Pool({ connectionString: databaseUrl, max: Number(process.env.EASYSIGN_DATABASE_POOL_MAX ?? 10) });
      created.on("error", () => { /* an idle connection dropped; the next query reconnects */ });
      app.addHook("onClose", async () => { await created.end(); });
      pool = created;
    }
    const store = new PostgresLedgerStore(pool, definition);
    app.addHook("onReady", async () => { await store.ready(); }); // refuse to start with a role that could bypass tenant isolation
    return store;
  };
  const audit = options.auditLog ?? (databaseUrl ? new AuditLog({ store: postgresStore(AUDIT_LEDGER) }) : new AuditLog({ filePath: process.env.EASYSIGN_AUDIT_FILE }));
  registerAuditRoutes(app, audit, guard);

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
    updateProgress(30);
    const data = job.data as { signedXml?: string; expectedCertificatePem?: string };
    if (!data.signedXml || typeof data.signedXml !== "string") {
      throw new Error("verify_signature requires data.signedXml (the XML with an enveloped XML-DSig signature).");
    }
    const result = signingEngine.verifyEcfXml(data.signedXml, data.expectedCertificatePem);
    updateProgress(100);
    return {
      verified: result.valid,
      errors: result.errors,
      verifiedAt: new Date().toISOString(),
      // cryptographic check only; conformance with the DGII XSD and test vectors is not claimed (see docs/SIGNING_CERTIFICATES.md)
      validationProfile: "XMLDSIG_CRYPTOGRAPHIC_ONLY",
    };
  });

  const auditSigning = (outcome: "success" | "error") => (job: { id: string; tenantId: string; operation: string }) => {
    audit.record({ correlationId: job.id, tenantId: job.tenantId || "platform", actor: "queue-worker", action: `job:${job.operation}`, resource: job.id, outcome, details: { operation: job.operation } })
      .catch(() => { /* auditing must never break signing */ });
  };
  queue.on("job:completed", auditSigning("success"));
  queue.on("job:failed", auditSigning("error"));

  registerTransactionRoutes(app, { queue, sseHub, webhookDispatcher });

  const registry = options.registry ?? new CertificateRegistry({ filePath: process.env.EASYSIGN_REGISTRY_FILE });
  registerRegistryRoutes(app, registry, guard);

  const disclosureFile = process.env.EASYSIGN_DISCLOSURE_FILE;
  const loadDisclosure = (): ServiceDisclosure | undefined => {
    if (!disclosureFile) return undefined;
    const d = JSON.parse(readFileSync(disclosureFile, "utf8")) as { version: string; config: Record<string, string> };
    return buildServiceDisclosure(d.config, d.version);
  };
  const disclosure = "disclosure" in options ? options.disclosure : loadDisclosure();
  const consentLedger = options.consentLedger ?? (databaseUrl ? new ConsentLedger({ store: postgresStore(CONSENT_LEDGER) }) : new ConsentLedger({ filePath: process.env.EASYSIGN_CONSENT_FILE }));
  registerConsentRoutes(app, consentLedger, disclosure, guard);
  registerWorkflowRoutes(app, options.workflow ?? new SignatureWorkflow({ filePath: process.env.EASYSIGN_WORKFLOW_FILE }), consentLedger, disclosure, guard, {
    publicBaseUrl: "publicBaseUrl" in options ? options.publicBaseUrl : process.env.EASYSIGN_PUBLIC_BASE_URL,
    providers: options.deliveryProviders,
    documents: options.documents ?? new DocumentStore(process.env.EASYSIGN_DOCS_DIR),
  });
  registerSignPage(app);

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
