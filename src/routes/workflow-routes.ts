import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ConsentLedger } from "../services/consent-ledger.js";
import type { ServiceDisclosure } from "../services/legal-notices.js";
import { NON_QUALIFIED_NOTICE } from "../services/legal-notices.js";
import { SignatureWorkflow, WorkflowError, type SignatureRequest } from "../services/signature-workflow.js";

const CreateSchema = z.object({
  tenantId: z.string().min(1),
  documentName: z.string().min(1).max(200),
  documentHash: z.string().length(64),
  ordering: z.enum(["sequential", "parallel"]).optional(),
  expiresInHours: z.number().int().optional(),
  signers: z.array(z.object({ name: z.string().min(1).max(120), email: z.string().max(200) })).min(1).max(20),
});
const TokenOnly = z.object({ token: z.string().min(20).max(200) });
const ConsentBody = TokenOnly.extend({ disclosureHash: z.string().length(64) });
const SignBody = TokenOnly.extend({ documentHash: z.string().length(64) });
const DeclineBody = TokenOnly.extend({ reason: z.string().max(300).default("") });
const CancelBody = z.object({ reason: z.string().max(300).default("") });

const STATUS: Record<WorkflowError["code"], number> = { NOT_FOUND: 404, INVALID_INPUT: 400, INVALID_STATE: 409, UNAUTHORIZED: 401, LOCKED: 429, EXPIRED: 410, NOT_YOUR_TURN: 409, DOCUMENT_MISMATCH: 409, CHAIN_BROKEN: 500 };

/** What a signer may see: never the other signers' emails. */
const signerView = (r: SignatureRequest, signerId: string, disclosure: ServiceDisclosure | undefined) => ({
  id: r.id, documentName: r.documentName, documentHash: r.documentHash, status: r.status, expiresAt: r.expiresAt, ordering: r.ordering,
  you: r.signers.find((s) => s.id === signerId), position: `${r.signers.find((s) => s.id === signerId)?.order}/${r.signers.length}`,
  notice: NON_QUALIFIED_NOTICE, disclosure,
});

/**
 * Admin routes need `Authorization: Bearer <EASYSIGN_ADMIN_TOKEN>` (fail closed). Signer routes are public but need the
 * signer's one-time token in the body. Interim access control until OIDC/RBAC (ES-005).
 */
export function registerWorkflowRoutes(app: FastifyInstance, workflow: SignatureWorkflow, consents: ConsentLedger, disclosure: ServiceDisclosure | undefined, adminToken: string | undefined): void {
  const admin = (request: FastifyRequest, reply: FastifyReply): string | undefined => {
    if (!adminToken) { reply.code(503).send({ error: "ADMIN_AUTH_NOT_CONFIGURED" }); return undefined; }
    const given = Buffer.from(String(request.headers.authorization ?? "").replace(/^Bearer\s+/i, ""));
    const expected = Buffer.from(adminToken);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) { reply.code(401).send({ error: "UNAUTHORIZED" }); return undefined; }
    return "workflow-admin";
  };
  const run = (reply: FastifyReply, fn: () => unknown, okCode = 200, hideNotFound = false) => {
    try { return reply.code(okCode).send(fn()); }
    catch (e) {
      if (e instanceof WorkflowError) {
        const code = hideNotFound && e.code === "NOT_FOUND" ? "UNAUTHORIZED" : e.code; // do not reveal which request ids exist to anonymous callers
        return reply.code(STATUS[code]).send({ error: code, message: code === "UNAUTHORIZED" ? "Invalid signer or token." : e.message });
      }
      throw e;
    }
  };
  const evidence = (request: FastifyRequest) => ({ ip: request.ip, userAgent: String(request.headers["user-agent"] ?? "").slice(0, 300) });
  const ids = (request: FastifyRequest) => request.params as { id: string; signerId: string };

  // ---- admin ----
  app.post("/v1/signature-workflows", async (request, reply) => {
    const actor = admin(request, reply); if (!actor) return;
    const body = CreateSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => workflow.create(body.data, actor), 201);
  });
  app.post("/v1/signature-workflows/:id/send", async (request, reply) => {
    if (!admin(request, reply)) return;
    if (!disclosure) return reply.code(503).send({ error: "DISCLOSURE_NOT_CONFIGURED", message: "The service disclosure must be published before requests can be sent (Annex II art. 33 b)." });
    return run(reply, () => workflow.send(ids(request).id));
  });
  app.post("/v1/signature-workflows/:id/cancel", async (request, reply) => {
    if (!admin(request, reply)) return;
    const body = CancelBody.safeParse(request.body ?? {});
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => workflow.cancel(ids(request).id, body.data.reason));
  });
  app.get("/v1/signature-workflows/:id", async (request, reply) => { if (!admin(request, reply)) return; return run(reply, () => workflow.get(ids(request).id)); });
  app.get("/v1/signature-workflows/:id/evidence", async (request, reply) => { if (!admin(request, reply)) return; return run(reply, () => workflow.evidence(ids(request).id)); });

  // ---- signer (one-time token) ----
  app.post("/v1/signature-workflows/:id/signers/:signerId/view", async (request, reply) => {
    const body = TokenOnly.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => signerView(workflow.view(id, signerId, body.data.token), signerId, disclosure), 200, true);
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/consent", async (request, reply) => {
    if (!disclosure) return reply.code(503).send({ error: "DISCLOSURE_NOT_CONFIGURED" });
    const body = ConsentBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => {
      const r = workflow.consent(id, signerId, body.data.token, body.data.disclosureHash, disclosure.hash, evidence(request));
      consents.grant({ tenantId: r.tenantId, subjectId: signerId, purpose: "signature_service_terms", textVersion: disclosure.version, text: disclosure.hash, evidence: { channel: "signature-workflow", ...evidence(request) } });
      return signerView(r, signerId, disclosure);
    }, 200, true);
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/sign", async (request, reply) => {
    const body = SignBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    // the next signer's token is NOT returned to this signer: it goes back to the administrator channel through /next-tokens
    return run(reply, () => {
      const out = workflow.sign(id, signerId, body.data.token, body.data.documentHash, evidence(request));
      pendingNext.set(id, [...(pendingNext.get(id) ?? []), ...out.next]);
      return signerView(out.request, signerId, disclosure);
    }, 200, true);
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/decline", async (request, reply) => {
    const body = DeclineBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => signerView(workflow.decline(id, signerId, body.data.token, body.data.reason), signerId, disclosure), 200, true);
  });

  // Tokens of signers whose turn has just come (sequential flow) are held in memory until the administrator collects
  // them to deliver by email/WhatsApp. Once a notification provider is integrated (ES-013) this goes away.
  const pendingNext = new Map<string, Array<{ signerId: string; name: string; email: string; order: number; token: string }>>();
  app.post("/v1/signature-workflows/:id/next-tokens", async (request, reply) => {
    if (!admin(request, reply)) return;
    const id = ids(request).id;
    const tokens = pendingNext.get(id) ?? [];
    pendingNext.delete(id);
    return reply.send({ tokens });
  });
}
