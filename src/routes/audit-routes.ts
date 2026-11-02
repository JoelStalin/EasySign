import { randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AuditLog } from "../services/audit-log.js";

const CORRELATION = /^[A-Za-z0-9._-]{8,80}$/;
/** Mutating requests on these prefixes are always audited, including denied ones. */
const AUDITED = ["/v1/registry/", "/v1/consents", "/v1/audit/export"];

/**
 * Assigns a correlation ID to every request (echoed in `X-Correlation-Id`) and records mutating calls to the
 * regulated endpoints with their outcome. Bodies are never stored, only the tenant when present and the status code.
 * Reading and exporting the ledger needs the admin token (fail closed).
 */
export function registerAuditRoutes(app: FastifyInstance, audit: AuditLog, adminToken: string | undefined): void {
  app.addHook("onRequest", async (request, reply) => {
    const given = request.headers["x-correlation-id"];
    const id = typeof given === "string" && CORRELATION.test(given) ? given : randomUUID();
    (request as unknown as { correlationId: string }).correlationId = id;
    reply.header("x-correlation-id", id);
  });

  app.addHook("onResponse", async (request, reply) => {
    const path = request.url.split("?")[0];
    const mutating = request.method !== "GET" && request.method !== "HEAD" && request.method !== "OPTIONS";
    if (!mutating || !AUDITED.some((p) => path.startsWith(p))) return;
    const body = (request.body ?? {}) as Record<string, unknown>;
    const code = reply.statusCode;
    audit.record({
      correlationId: (request as unknown as { correlationId: string }).correlationId,
      tenantId: typeof body.tenantId === "string" && body.tenantId ? body.tenantId : "platform",
      actor: code === 401 || code === 503 ? "anonymous" : "registry-admin",
      action: `${request.method} ${request.routeOptions?.url ?? path}`,
      resource: path,
      outcome: code < 400 ? "success" : code === 401 || code === 403 || code === 503 ? "denied" : "error",
      details: { statusCode: code },
    });
  });

  const authorized = (header: unknown): boolean => {
    if (!adminToken) return false;
    const given = Buffer.from(String(header ?? "").replace(/^Bearer\s+/i, ""));
    const expected = Buffer.from(adminToken);
    return given.length === expected.length && timingSafeEqual(given, expected);
  };

  app.get("/v1/audit/events", async (request, reply) => {
    if (!adminToken) return reply.code(503).send({ error: "ADMIN_AUTH_NOT_CONFIGURED" });
    if (!authorized(request.headers.authorization)) return reply.code(401).send({ error: "UNAUTHORIZED" });
    const q = request.query as Record<string, string | undefined>;
    return { chainValid: audit.verifyChain(), events: audit.query({ tenantId: q.tenantId, action: q.action, correlationId: q.correlationId, from: q.from, to: q.to, limit: q.limit ? Number(q.limit) : undefined }) };
  });

  app.post("/v1/audit/export", async (request, reply) => {
    if (!adminToken) return reply.code(503).send({ error: "ADMIN_AUTH_NOT_CONFIGURED" });
    if (!authorized(request.headers.authorization)) return reply.code(401).send({ error: "UNAUTHORIZED" });
    const tenantId = (request.body as { tenantId?: string } | undefined)?.tenantId;
    if (!tenantId) return reply.code(400).send({ error: "INVALID_REQUEST", message: "tenantId is required." });
    return audit.exportEvidence(tenantId);
  });
}
