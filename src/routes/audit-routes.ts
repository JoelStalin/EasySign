import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { AuditError, type AuditLog } from "../services/audit-log.js";
import { Guard, tenantOf, type Role } from "../auth/guard.js";

const CORRELATION = /^[A-Za-z0-9._-]{8,80}$/;
/** Mutating requests on these prefixes are always audited, including denied ones. */
const AUDITED = ["/v1/registry/", "/v1/consents", "/v1/audit/export", "/v1/signature-workflows"];
const AUDIT_READERS: Role[] = ["platform_admin", "tenant_admin", "auditor"];

/**
 * Assigns a correlation ID to every request (echoed in `X-Correlation-Id`) and records mutating calls to the
 * regulated endpoints with their outcome. Bodies are never stored, only the tenant when present and the status code.
 * The actor is the authenticated principal's subject. Reading and exporting the ledger needs an auditing role and is
 * limited to the caller's own tenant, except for platform admins.
 */
export function registerAuditRoutes(app: FastifyInstance, audit: AuditLog, guard: Guard): void {
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
    await audit.record({
      correlationId: (request as unknown as { correlationId: string }).correlationId,
      tenantId: request.principal && !request.principal.roles.includes("platform_admin") && request.principal.tenantId ? request.principal.tenantId : typeof body.tenantId === "string" && body.tenantId ? body.tenantId : "platform",
      actor: path.includes("/signers/") ? "signer" : request.principal?.sub ?? "anonymous",
      action: `${request.method} ${request.routeOptions?.url ?? path}`,
      resource: path,
      outcome: code < 400 ? "success" : code === 401 || code === 403 || code === 503 ? "denied" : "error",
      details: typeof body.tenantId === "string" && body.tenantId ? { statusCode: code, targetTenant: body.tenantId } : { statusCode: code },
    });
  });

  app.get("/v1/audit/events", async (request, reply) => {
    const p = await guard.require(request, reply, AUDIT_READERS);
    if (!p) return;
    const q = request.query as Record<string, string | undefined>;
    const platform = p.roles.includes("platform_admin");
    const tenantId = platform ? q.tenantId : p.tenantId; // tenant roles can only ever see their own tenant
    if (!platform && !tenantId) return reply.code(403).send({ error: "FORBIDDEN", message: "Your token has no tenant." });
    try {
      const events = await audit.query({ tenantId, action: q.action, correlationId: q.correlationId, from: q.from, to: q.to, limit: q.limit ? Number(q.limit) : undefined });
      return { chainValid: await audit.verifyChain(tenantId), events };
    } catch (e) {
      // with PostgreSQL the ledger is isolated per tenant, so even a platform admin has to name the tenant
      if (e instanceof AuditError) return reply.code(e.code === "TENANT_REQUIRED" ? 400 : 500).send({ error: e.code, message: e.message });
      throw e;
    }
  });

  app.post("/v1/audit/export", async (request, reply) => {
    const tenantId = tenantOf(request.body);
    const p = await guard.require(request, reply, AUDIT_READERS, tenantId);
    if (!p) return;
    if (!tenantId) return reply.code(400).send({ error: "INVALID_REQUEST", message: "tenantId is required." });
    return audit.exportEvidence(tenantId);
  });
}
