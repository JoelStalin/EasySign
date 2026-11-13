import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { QueueEngine } from "../queue/queue-engine.js";
import type { SseHub } from "../services/sse-hub.js";
import type { WebhookDispatcher } from "../services/webhook-dispatcher.js";

const AsyncTransactionSchema = z.object({
  tenantId: z.string().min(1),
  operation: z.enum(["sign_ecf_xml", "sign_pdf", "verify_signature", "batch_sign_item"]),
  data: z.record(z.any()),
  priority: z.enum(["critical", "high", "normal", "bulk"]).optional(),
  idempotencyKey: z.string().optional(),
  webhookUrl: z.string().url().optional(),
  webhookSecret: z.string().optional(),
  timeoutMs: z.number().int().positive().optional(),
  maxRetries: z.number().int().min(0).max(10).optional(),
});

const BatchTransactionSchema = z.object({
  tenantId: z.string().min(1),
  items: z.array(
    z.object({
      operation: z.enum(["sign_ecf_xml", "sign_pdf", "verify_signature", "batch_sign_item"]),
      data: z.record(z.any()),
      priority: z.enum(["critical", "high", "normal", "bulk"]).optional(),
      idempotencyKey: z.string().optional(),
    })
  ).min(1).max(5000),
  webhookUrl: z.string().url().optional(),
  batchPriority: z.enum(["critical", "high", "normal", "bulk"]).optional(),
});

export function registerTransactionRoutes(
  app: FastifyInstance,
  services: {
    queue: QueueEngine;
    sseHub: SseHub;
    webhookDispatcher: WebhookDispatcher;
  }
): void {
  const { queue, sseHub, webhookDispatcher } = services;

  queue.on("job:completed", (job) => {
    if (job.webhookUrl) {
      webhookDispatcher.dispatchJobNotification(job).catch(() => {});
    }
  });
  queue.on("job:failed", (job) => {
    if (job.webhookUrl) {
      webhookDispatcher.dispatchJobNotification(job).catch(() => {});
    }
  });

  app.post("/v1/transactions/async", async (request, reply) => {
    const headerIdempotencyKey = request.headers["idempotency-key"] as string | undefined;
    const body = (request.body as Record<string, unknown>) || {};
    if (headerIdempotencyKey && !body.idempotencyKey) {
      body.idempotencyKey = headerIdempotencyKey;
    }

    const parsed = AsyncTransactionSchema.safeParse(body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "INVALID_TRANSACTION_PAYLOAD",
        issues: parsed.error.issues,
      });
    }

    try {
      const { job, isExisting } = await queue.enqueue(parsed.data);
      const metrics = queue.getMetrics();

      return reply.code(202).send({
        jobId: job.id,
        status: job.status,
        isIdempotentReplay: isExisting,
        priority: job.priority,
        trackingUrl: `/v1/jobs/${job.id}`,
        streamUrl: `/v1/jobs/${job.id}/stream`,
        idempotencyKey: job.idempotencyKey,
        queuePosition: metrics.waiting,
        estimatedWaitMs: metrics.waiting * 25,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("QUEUE_CAPACITY_EXCEEDED")) {
        return reply.code(429).send({
          error: "QUEUE_CONGESTION_BACKPRESSURE",
          message: msg,
          retryAfterSeconds: 5,
        });
      }
      return reply.code(500).send({ error: "QUEUE_INGESTION_FAILED", message: msg });
    }
  });

  app.post("/v1/transactions/batch", async (request, reply) => {
    const parsed = BatchTransactionSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "INVALID_BATCH_PAYLOAD",
        issues: parsed.error.issues,
      });
    }

    try {
      const batchRecord = await queue.enqueueBatch(parsed.data);
      return reply.code(202).send({
        batchId: batchRecord.batchId,
        total: batchRecord.total,
        status: batchRecord.status,
        trackingUrl: `/v1/batches/${batchRecord.batchId}`,
        tenantStreamUrl: `/v1/tenants/${batchRecord.tenantId}/stream`,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return reply.code(500).send({ error: "BATCH_INGESTION_FAILED", message: msg });
    }
  });

  app.get<{ Params: { jobId: string } }>("/v1/jobs/:jobId", async (request, reply) => {
    const { jobId } = request.params;
    const job = queue.getJob(jobId);

    if (!job) {
      return reply.code(404).send({
        error: "JOB_NOT_FOUND",
        message: `Job with ID '${jobId}' was not found.`,
      });
    }

    return reply.send({
      id: job.id,
      tenantId: job.tenantId,
      operation: job.operation,
      status: job.status,
      progress: job.progress,
      attempts: job.attempts,
      queuedAt: job.queuedAt,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      durationMs: job.durationMs,
      idempotencyKey: job.idempotencyKey,
      result: job.result,
      error: job.error,
    });
  });

  app.get<{ Params: { jobId: string } }>("/v1/jobs/:jobId/stream", async (request, reply) => {
    const { jobId } = request.params;
    sseHub.registerJobStream(jobId, reply);
  });

  app.get<{ Params: { batchId: string } }>("/v1/batches/:batchId", async (request, reply) => {
    const { batchId } = request.params;
    const batch = queue.getBatch(batchId);

    if (!batch) {
      return reply.code(404).send({
        error: "BATCH_NOT_FOUND",
        message: `Batch with ID '${batchId}' was not found.`,
      });
    }

    return reply.send(batch);
  });

  app.get<{ Params: { tenantId: string } }>("/v1/tenants/:tenantId/stream", async (request, reply) => {
    const { tenantId } = request.params;
    sseHub.registerTenantStream(tenantId, reply);
  });

  app.get("/v1/queue/metrics", async () => {
    return queue.getMetrics();
  });

  app.post("/v1/queue/pause", async () => {
    queue.pause();
    return { success: true, message: "Queue engine paused." };
  });

  app.post("/v1/queue/resume", async () => {
    queue.resume();
    return { success: true, message: "Queue engine resumed." };
  });
}
