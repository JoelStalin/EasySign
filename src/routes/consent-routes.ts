import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { ConsentError, type ConsentLedger } from "../services/consent-ledger.js";
import { NON_QUALIFIED_NOTICE, SIGNATURE_KINDS_EXPLANATION, type ServiceDisclosure } from "../services/legal-notices.js";

const PURPOSES = ["signature_service_terms", "personal_data_processing", "identity_verification", "marketing"] as const;
const Evidence = z.object({ channel: z.string().min(1).max(40), ip: z.string().max(64).optional(), userAgent: z.string().max(300).optional() });
const GrantSchema = z.object({ tenantId: z.string().min(1), subjectId: z.string().min(1), purpose: z.enum(PURPOSES), textVersion: z.string().min(1), text: z.string().min(1), evidence: Evidence });
const WithdrawSchema = z.object({ tenantId: z.string().min(1), subjectId: z.string().min(1), purpose: z.enum(PURPOSES), evidence: Evidence });

const STATUS: Record<ConsentError["code"], number> = { INVALID_INPUT: 400, NOT_GRANTED: 409, CHAIN_BROKEN: 500 };

/** Public: the mandatory disclosures. Protected (Bearer admin token, fail closed): consent writes and history. */
export function registerConsentRoutes(app: FastifyInstance, ledger: ConsentLedger, disclosure: ServiceDisclosure | undefined, adminToken: string | undefined): void {
  const authorized = (request: FastifyRequest, reply: FastifyReply): boolean => {
    if (!adminToken) { reply.code(503).send({ error: "ADMIN_AUTH_NOT_CONFIGURED" }); return false; }
    const given = Buffer.from(String(request.headers.authorization ?? "").replace(/^Bearer\s+/i, ""));
    const expected = Buffer.from(adminToken);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) { reply.code(401).send({ error: "UNAUTHORIZED" }); return false; }
    return true;
  };
  const guard = (reply: FastifyReply, fn: () => unknown, okCode = 200) => {
    try { return reply.code(okCode).send(fn()); }
    catch (e) { if (e instanceof ConsentError) return reply.code(STATUS[e.code]).send({ error: e.code, message: e.message }); throw e; }
  };

  app.get("/v1/legal/disclosure", async (_req, reply) => {
    if (!disclosure) return reply.code(503).send({ error: "DISCLOSURE_NOT_CONFIGURED", nonQualifiedNotice: NON_QUALIFIED_NOTICE, signatureKinds: SIGNATURE_KINDS_EXPLANATION });
    return disclosure;
  });

  app.post("/v1/consents", async (request, reply) => {
    if (!authorized(request, reply)) return;
    const body = GrantSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return guard(reply, () => ledger.grant(body.data), 201);
  });
  app.post("/v1/consents/withdraw", async (request, reply) => {
    if (!authorized(request, reply)) return;
    const body = WithdrawSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return guard(reply, () => ledger.withdraw(body.data.tenantId, body.data.subjectId, body.data.purpose, body.data.evidence));
  });
  app.get("/v1/consents/:tenantId/:subjectId", async (request, reply) => {
    if (!authorized(request, reply)) return;
    const p = request.params as { tenantId: string; subjectId: string };
    const marketing = ledger.hasConsent(p.tenantId, p.subjectId, "marketing");
    return { marketingAllowed: marketing, history: ledger.history(p.tenantId, p.subjectId) };
  });
}
