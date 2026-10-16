import type { FastifyReply } from "fastify";
import type { QueueEngine } from "../queue/queue-engine.js";
import type { JobRecord, BatchRecord } from "../queue/types.js";

export class SseHub {
  private readonly jobSubscribers = new Map<string, Set<FastifyReply>>();
  private readonly tenantSubscribers = new Map<string, Set<FastifyReply>>();

  constructor(private readonly queue: QueueEngine) {
    this.bindEvents();
  }

  private bindEvents(): void {
    this.queue.on("job:progress", ({ jobId, progress, status }) => {
      this.broadcastToJob(jobId, "progress", { jobId, progress, status });
    });

    this.queue.on("job:completed", (job: JobRecord) => {
      this.broadcastToJob(job.id, "completed", {
        jobId: job.id,
        status: job.status,
        progress: 100,
        result: job.result,
        durationMs: job.durationMs,
      });
      this.closeJobSubscribers(job.id);
    });

    this.queue.on("job:failed", (job: JobRecord) => {
      this.broadcastToJob(job.id, "failed", {
        jobId: job.id,
        status: job.status,
        error: job.error,
        durationMs: job.durationMs,
      });
      this.closeJobSubscribers(job.id);
    });

    this.queue.on("batch:progress", (batch: BatchRecord) => {
      this.broadcastToTenant(batch.tenantId, "batch:progress", batch);
    });

    this.queue.on("batch:completed", (batch: BatchRecord) => {
      this.broadcastToTenant(batch.tenantId, "batch:completed", batch);
    });
  }

  public registerJobStream(jobId: string, reply: FastifyReply): void {
    const raw = reply.raw;
    raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "Access-Control-Allow-Origin": "*",
    });

    raw.write(`: connected to easysign stream for job ${jobId}\n\n`);

    if (!this.jobSubscribers.has(jobId)) {
      this.jobSubscribers.set(jobId, new Set());
    }
    this.jobSubscribers.get(jobId)!.add(reply);

    const job = this.queue.getJob(jobId);
    if (job) {
      raw.write(`event: state\ndata: ${JSON.stringify({
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        queuedAt: job.queuedAt,
      })}\n\n`);

      if (job.status === "completed" || job.status === "failed") {
        setImmediate(() => this.closeJobSubscribers(jobId));
      }
    }

    raw.on("close", () => {
      const subs = this.jobSubscribers.get(jobId);
      if (subs) {
        subs.delete(reply);
        if (subs.size === 0) this.jobSubscribers.delete(jobId);
      }
    });
  }

  public registerTenantStream(tenantId: string, reply: FastifyReply): void {
    const raw = reply.raw;
    raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "Access-Control-Allow-Origin": "*",
    });

    raw.write(`: connected to easysign global stream for tenant ${tenantId}\n\n`);

    if (!this.tenantSubscribers.has(tenantId)) {
      this.tenantSubscribers.set(tenantId, new Set());
    }
    this.tenantSubscribers.get(tenantId)!.add(reply);

    raw.on("close", () => {
      const subs = this.tenantSubscribers.get(tenantId);
      if (subs) {
        subs.delete(reply);
        if (subs.size === 0) this.tenantSubscribers.delete(tenantId);
      }
    });
  }

  private broadcastToJob(jobId: string, eventName: string, data: unknown): void {
    const subs = this.jobSubscribers.get(jobId);
    if (!subs || subs.size === 0) return;

    const message = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const reply of subs) {
      try {
        reply.raw.write(message);
      } catch {
        // Dropped
      }
    }
  }

  private broadcastToTenant(tenantId: string, eventName: string, data: unknown): void {
    const subs = this.tenantSubscribers.get(tenantId);
    if (!subs || subs.size === 0) return;

    const message = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const reply of subs) {
      try {
        reply.raw.write(message);
      } catch {
        // Dropped
      }
    }
  }

  private closeJobSubscribers(jobId: string): void {
    const subs = this.jobSubscribers.get(jobId);
    if (!subs) return;
    for (const reply of subs) {
      try {
        reply.raw.end();
      } catch {
        // Safe close
      }
    }
    this.jobSubscribers.delete(jobId);
  }
}
