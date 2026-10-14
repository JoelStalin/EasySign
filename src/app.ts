import Fastify from 'fastify';
import { z } from 'zod';

export function buildApp() {
  const app = Fastify({ logger: true });
  app.get('/v1/system/status', async () => ({ service: 'easysign', mode: 'sandbox', accredited: false }));
  const requestSchema = z.object({ tenantId: z.string().uuid(), documentId: z.string().uuid(), signerId: z.string().uuid() });
  app.post('/v1/signature-requests', async (request, reply) => {
    const parsed = requestSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: 'INVALID_REQUEST', issues: parsed.error.issues });
    return reply.code(501).send({ error: 'NOT_IMPLEMENTED', message: 'Signing is disabled until identity, authorization and evidence controls are implemented.' });
  });
  return app;
}
