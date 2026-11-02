import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { CertificateRegistry, RegistryError } from "../services/certificate-registry.js";
import type { Guard } from "../auth/guard.js";

const REASONS = ["unspecified", "keyCompromise", "caCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "privilegeWithdrawn"] as const;

const RegisterSchema = z.object({
  serial: z.string().min(1).max(64),
  subject: z.string().min(1).max(500),
  issuer: z.string().min(1).max(500),
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
});
const RevokeSchema = z.object({ reason: z.enum(REASONS).optional(), requestedAt: z.string().datetime().optional() });
const ListSchema = z.object({
  status: z.enum(["active", "suspended", "revoked"]).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const STATUS_BY_CODE: Record<RegistryError["code"], number> = { NOT_FOUND: 404, ALREADY_EXISTS: 409, INVALID_TRANSITION: 409, INVALID_INPUT: 400, CHAIN_BROKEN: 500 };

/**
 * Reads are public (Annex II art. 31). Writes need `Authorization: Bearer <EASYSIGN_ADMIN_TOKEN>` and fail closed (503)
 * when no token is configured. This is an interim control until OIDC and RBAC (ES-005) replace it.
 */
export function registerRegistryRoutes(app: FastifyInstance, registry: CertificateRegistry, guard: Guard): void {
  const authorize = async (request: FastifyRequest, reply: FastifyReply): Promise<string | undefined> => (await guard.require(request, reply, ["platform_admin"]))?.sub;
  const run = (reply: FastifyReply, fn: () => unknown, okCode = 200) => {
    try { return reply.code(okCode).send(fn()); }
    catch (e) {
      if (e instanceof RegistryError) return reply.code(STATUS_BY_CODE[e.code]).send({ error: e.code, message: e.message });
      throw e;
    }
  };

  app.get("/v1/registry/certificates", async (request, reply) => {
    const q = ListSchema.safeParse(request.query);
    if (!q.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: q.error.issues });
    return registry.list(q.data);
  });
  app.get("/v1/registry/certificates/:serial", async (request, reply) => run(reply, () => registry.get((request.params as { serial: string }).serial)));
  app.get("/v1/registry/revocations", async () => registry.revocationList());

  app.post("/v1/registry/certificates", async (request, reply) => {
    const actor = await authorize(request, reply); if (!actor) return;
    const body = RegisterSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => registry.register({ ...body.data, actor }), 201);
  });
  app.post("/v1/registry/certificates/:serial/suspend", async (request, reply) => {
    const actor = await authorize(request, reply); if (!actor) return;
    return run(reply, () => registry.suspend((request.params as { serial: string }).serial, actor));
  });
  app.post("/v1/registry/certificates/:serial/reactivate", async (request, reply) => {
    const actor = await authorize(request, reply); if (!actor) return;
    return run(reply, () => registry.reactivate((request.params as { serial: string }).serial, actor));
  });
  app.post("/v1/registry/certificates/:serial/revoke", async (request, reply) => {
    const actor = await authorize(request, reply); if (!actor) return;
    const body = RevokeSchema.safeParse(request.body ?? {});
    if (!body.success) return reply.code(400).send({ error: "INVALID_REQUEST", issues: body.error.issues });
    return run(reply, () => registry.revoke((request.params as { serial: string }).serial, actor, body.data.reason, body.data.requestedAt));
  });
  app.get("/v1/registry/certificates/:serial/history", async (request, reply) => {
    const actor = await authorize(request, reply); if (!actor) return;
    return run(reply, () => registry.history((request.params as { serial: string }).serial));
  });
}
