import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { CHANNELS, prepareDelivery, type DeliveryProvider, type DeliveryResult } from "../services/delivery.js";
import type { ConsentLedger } from "../services/consent-ledger.js";
import type { ServiceDisclosure } from "../services/legal-notices.js";
import { NON_QUALIFIED_NOTICE } from "../services/legal-notices.js";
import { READERS, WRITERS, tenantOf, type Guard } from "../auth/guard.js";
import { DocumentError, DocumentStore, MAX_DOCUMENT_BYTES, safeFileName } from "../services/document-store.js";
import { SignatureWorkflow, WorkflowError, type IssuedToken, type SignatureRequest } from "../services/signature-workflow.js";

const Channel = z.enum(CHANNELS as unknown as [string, ...string[]]);
const CreateSchema = z.object({
  tenantId: z.string().min(1),
  documentName: z.string().min(1).max(200),
  documentHash: z.string().length(64),
  ordering: z.enum(["sequential", "parallel"]).optional(),
  expiresInHours: z.number().int().optional(),
  signers: z.array(z.object({ name: z.string().min(1).max(120), email: z.string().max(200), channel: Channel.optional(), phone: z.string().max(20).optional() })).min(1).max(20),
});
const TokenOnly = z.object({ token: z.string().min(20).max(200) });
const ConsentBody = TokenOnly.extend({ disclosureHash: z.string().length(64) });
const SignBody = TokenOnly.extend({ documentHash: z.string().length(64) });
const DeclineBody = TokenOnly.extend({ reason: z.string().max(300).default("") });
const CancelBody = z.object({ reason: z.string().max(300).default("") });
const ReissueBody = z.object({ channel: Channel.optional() });

const STATUS: Record<WorkflowError["code"], number> = { NOT_FOUND: 404, INVALID_INPUT: 400, INVALID_STATE: 409, UNAUTHORIZED: 401, LOCKED: 429, EXPIRED: 410, NOT_YOUR_TURN: 409, DOCUMENT_MISMATCH: 409, CHAIN_BROKEN: 500 };

/** What a signer may see: never the other signers' emails or phones. */
const signerView = (r: SignatureRequest, signerId: string, disclosure: ServiceDisclosure | undefined) => {
  const you = r.signers.find((s) => s.id === signerId);
  return {
    id: r.id, documentName: r.documentName, documentHash: r.documentHash, status: r.status, expiresAt: r.expiresAt, ordering: r.ordering,
    you: you && { id: you.id, name: you.name, order: you.order, status: you.status, documentViewed: Boolean(you.documentViewedAt) }, document: r.document, documentViewed: Boolean(you?.documentViewedAt), position: `${you?.order}/${r.signers.length}`,
    notice: NON_QUALIFIED_NOTICE, disclosure,
  };
};

export interface WorkflowRouteOptions {
  /** Public origin used to build signing links, e.g. https://firma.example.do */
  publicBaseUrl?: string;
  providers?: DeliveryProvider[];
  documents?: DocumentStore;
}

/**
 * Admin routes need `Authorization: Bearer <EASYSIGN_ADMIN_TOKEN>` (fail closed). Signer routes are public but need the
 * signer's one-time token in the body. Interim access control until OIDC/RBAC (ES-005).
 */
export function registerWorkflowRoutes(
  app: FastifyInstance, workflow: SignatureWorkflow, consents: ConsentLedger, disclosure: ServiceDisclosure | undefined, guard: Guard, options: WorkflowRouteOptions = {}
): void {
  const documents = options.documents ?? new DocumentStore();
  app.addContentTypeParser(["application/pdf", "image/png", "image/jpeg", "text/plain", "application/octet-stream"], { parseAs: "buffer", bodyLimit: MAX_DOCUMENT_BYTES }, (_req, body, done) => done(null, body));
  const admin = async (request: FastifyRequest, reply: FastifyReply, roles: typeof WRITERS, tenantId?: string, hideForeign = false): Promise<string | undefined> => (await guard.require(request, reply, roles, tenantId, hideForeign))?.sub;
  /** Authorizes an action on an existing request: the tenant is the request's own; an unknown or foreign id looks the same to tenant roles. */
  const forRequest = async (request: FastifyRequest, reply: FastifyReply, roles: typeof WRITERS = WRITERS): Promise<string | undefined> => {
    let tenant = "";
    try { tenant = workflow.get((request.params as { id: string }).id).tenantId; } catch { /* unknown id: matches no tenant */ }
    return admin(request, reply, roles, tenant, true);
  };
  const run = async (reply: FastifyReply, fn: () => unknown | Promise<unknown>, okCode = 200, hideNotFound = false) => {
    try { return reply.code(okCode).send(await fn()); }
    catch (e) {
      if (e instanceof WorkflowError) {
        const code = hideNotFound && e.code === "NOT_FOUND" ? "UNAUTHORIZED" : e.code; // do not reveal which request ids exist to anonymous callers
        return reply.code(STATUS[code]).send({ error: code, message: code === "UNAUTHORIZED" ? "Invalid signer or token." : e.message });
      }
      if (e instanceof DocumentError) {
        if (e.code === "KEY_UNAVAILABLE" || e.code === "DECRYPT_FAILED") {
          reply.log.error(e); // the detail (key id, cause) stays in the server log, not in the response
          return reply.code(500).send({ error: "DOCUMENT_UNAVAILABLE", message: "The stored document could not be read." });
        }
        return reply.code(e.code === "TOO_LARGE" ? 413 : e.code === "NOT_FOUND" ? 404 : 400).send({ error: e.code, message: e.message });
      }
      throw e;
    }
  };
  const evidence = (request: FastifyRequest) => ({ ip: request.ip, userAgent: String(request.headers["user-agent"] ?? "").slice(0, 300) });
  const ids = (request: FastifyRequest) => request.params as { id: string; signerId: string };
  const deliver = (tokens: IssuedToken[], requestId: string) =>
    prepareDelivery(tokens, requestId, workflow.get(requestId).documentName, options.publicBaseUrl, options.providers);
  /** Tokens already delivered by a provider are not echoed back to the caller. */
  const undelivered = (tokens: IssuedToken[], deliveries: DeliveryResult[]) => tokens.filter((t) => deliveries.find((d) => d.signerId === t.signerId)?.status !== "sent");

  // Links of signers whose turn has just come (sequential flow) that no provider delivered wait here until the
  // administrator collects them. They are lost on restart: use /reissue then.
  const pendingNext = new Map<string, DeliveryResult[]>();

  // ---- admin ----
  app.post("/v1/signature-workflows", async (request, reply) => {
    const actor = await admin(request, reply, WRITERS, tenantOf(request.body)); if (!actor) return;
    const body = CreateSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => workflow.create(body.data as Parameters<SignatureWorkflow["create"]>[0], actor), 201);
  });
  app.post("/v1/signature-workflows/:id/send", async (request, reply) => {
    if (!(await forRequest(request, reply))) return;
    if (!disclosure) return reply.code(503).send({ error: "DISCLOSURE_NOT_CONFIGURED", message: "The service disclosure must be published before requests can be sent (Annex II art. 33 b)." });
    const sendBody = (request.body ?? {}) as { acknowledgeNoDocument?: boolean };
    try {
      if (!workflow.get(ids(request).id).document && sendBody.acknowledgeNoDocument !== true) {
        return reply.code(409).send({ error: "DOCUMENT_REQUIRED", message: "Upload the document (PUT .../document) before sending, or confirm with acknowledgeNoDocument: true that signers will not be able to open it on the platform." });
      }
    } catch (e) {
      if (e instanceof WorkflowError) return reply.code(STATUS[e.code]).send({ error: e.code, message: e.message });
      throw e;
    }
    return run(reply, async () => {
      const { request: r, tokens } = workflow.send(ids(request).id);
      const deliveries = await deliver(tokens, r.id);
      return { request: r, deliveries, tokens: undelivered(tokens, deliveries) };
    });
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/reissue", async (request, reply) => {
    if (!(await forRequest(request, reply))) return;
    const body = ReissueBody.safeParse(request.body ?? {});
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    const { id, signerId } = ids(request);
    return run(reply, async () => {
      const t = workflow.reissue(id, signerId, body.data.channel as never);
      const deliveries = await deliver([t], id);
      return { deliveries, tokens: undelivered([t], deliveries) };
    });
  });
  app.post("/v1/signature-workflows/:id/cancel", async (request, reply) => {
    if (!(await forRequest(request, reply))) return;
    const body = CancelBody.safeParse(request.body ?? {});
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => workflow.cancel(ids(request).id, body.data.reason));
  });
  app.get("/v1/signature-workflows/:id", async (request, reply) => { if (!(await forRequest(request, reply, READERS))) return; return run(reply, () => workflow.get(ids(request).id)); });
  app.get("/v1/signature-workflows/:id/evidence", async (request, reply) => { if (!(await forRequest(request, reply, READERS))) return; return run(reply, () => workflow.evidence(ids(request).id)); });
  app.post("/v1/signature-workflows/:id/next-tokens", async (request, reply) => {
    if (!(await forRequest(request, reply))) return;
    const id = ids(request).id;
    const deliveries = pendingNext.get(id) ?? [];
    pendingNext.delete(id);
    return reply.send({ deliveries, tokens: deliveries.filter((d) => d.signingUrl).map((d) => ({ signerId: d.signerId, token: new URL(d.signingUrl!).hash.slice(1) })) });
  });

  // ---- signer (one-time token) ----
  app.post("/v1/signature-workflows/:id/signers/:signerId/view", async (request, reply) => {
    const body = TokenOnly.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => signerView(workflow.view(id, signerId, body.data.token), signerId, disclosure), 200, true);
  });
  app.put("/v1/signature-workflows/:id/document", async (request, reply) => {
    if (!(await forRequest(request, reply))) return;
    const raw = request.body;
    if (!Buffer.isBuffer(raw)) return reply.code(415).send({ error: "UNSUPPORTED_MEDIA_TYPE", message: "Send the document as application/pdf, image/png, image/jpeg or text/plain." });
    return run(reply, () => {
      const r = workflow.get(ids(request).id);
      const stored = documents.put(raw);
      if (stored.hash !== r.documentHash) throw new WorkflowError("DOCUMENT_MISMATCH", "The SHA-256 of the uploaded file does not match the documentHash of this request.");
      return workflow.attachDocument(r.id, { contentType: stored.contentType, size: stored.size, fileName: safeFileName(String(request.headers["x-file-name"] ?? ""), stored.contentType) });
    });
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/document", async (request, reply) => {
    const body = TokenOnly.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => {
      const meta = workflow.documentAccess(id, signerId, body.data.token);
      const { bytes, contentType } = documents.get(workflow.get(id).documentHash);
      reply.header("content-type", contentType).header("content-disposition", `inline; filename="${meta.fileName}"`).header("x-content-type-options", "nosniff")
        .header("cache-control", "no-store").header("content-security-policy", "sandbox; default-src 'none'");
      return bytes;
    }, 200, true);
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
    // the next signer's link is NOT returned to this signer: a provider delivers it, or the administrator collects it
    return run(reply, async () => {
      const out = workflow.sign(id, signerId, body.data.token, body.data.documentHash, evidence(request));
      if (out.next.length) {
        const deliveries = await deliver(out.next, id);
        const manual = deliveries.filter((d) => d.status !== "sent");
        if (manual.length) pendingNext.set(id, [...(pendingNext.get(id) ?? []), ...manual]);
      }
      return signerView(out.request, signerId, disclosure);
    }, 200, true);
  });
  app.post("/v1/signature-workflows/:id/signers/:signerId/decline", async (request, reply) => {
    const body = DeclineBody.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST" });
    const { id, signerId } = ids(request);
    return run(reply, () => signerView(workflow.decline(id, signerId, body.data.token, body.data.reason), signerId, disclosure), 200, true);
  });
}
