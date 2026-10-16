import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type {
  JobPriority,
  JobRecord,
  JobStatus,
  BatchRecord,
  QueueMetrics,
  QueueOptions,
  OperationType,
} from "./types.js";

const PRIORITY_WEIGHTS: Record<JobPriority, number> = {
  critical: 4,
  high: 3,
  normal: 2,
  bulk: 1,
};

export type JobHandler<T = unknown, R = unknown> = (
  job: JobRecord<T, R>,
  updateProgress: (percent: number) => void
) => Promise<R>;

export class QueueEngine extends EventEmitter {
  private readonly waitingQueue: JobRecord[] = [];
  private readonly activeJobs = new Map<string, JobRecord>();
  private readonly completedJobs = new Map<string, JobRecord>();
  private readonly failedJobs = new Map<string, JobRecord>();
  private readonly deadLetterJobs = new Map<string, JobRecord>();
  private readonly idempotencyIndex = new Map<string, string>(); // tenant:key -> jobId
  private readonly batches = new Map<string, BatchRecord>();

  private readonly handlers = new Map<OperationType, JobHandler>();
  private readonly concurrency: number;
  private readonly maxQueueCapacity: number;
  private readonly defaultMaxRetries: number;
  private readonly defaultTimeoutMs: number;
  private readonly retryBaseDelayMs: number;
  private readonly retryMaxDelayMs: number;

  private isPaused = false;
  private completedTimestamps: number[] = [];
  private totalDurationMs = 0;
  private totalCompletedCount = 0;

  constructor(options: QueueOptions = {}) {
    super();
    this.concurrency = options.concurrency ?? 10;
    this.maxQueueCapacity = options.maxQueueCapacity ?? 50000;
    this.defaultMaxRetries = options.defaultMaxRetries ?? 3;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 30000;
    this.retryBaseDelayMs = options.retryBaseDelayMs ?? 200;
    this.retryMaxDelayMs = options.retryMaxDelayMs ?? 5000;
  }

  public registerHandler<T, R>(
    operation: OperationType,
    handler: JobHandler<T, R>
  ): void {
    this.handlers.set(operation, handler as JobHandler);
  }

  public async enqueue<T = unknown, R = unknown>(params: {
    tenantId: string;
    operation: OperationType;
    data: T;
    priority?: JobPriority;
    idempotencyKey?: string;
    webhookUrl?: string;
    webhookSecret?: string;
    maxRetries?: number;
    timeoutMs?: number;
    batchId?: string;
  }): Promise<{ job: JobRecord<T, R>; isExisting: boolean }> {
    // 1. Idempotency Check
    if (params.idempotencyKey) {
      const idxKey = `${params.tenantId}:${params.idempotencyKey}`;
      const existingJobId = this.idempotencyIndex.get(idxKey);
      if (existingJobId) {
        const existingJob =
          this.activeJobs.get(existingJobId) ||
          this.completedJobs.get(existingJobId) ||
          this.waitingQueue.find((j) => j.id === existingJobId) ||
          this.failedJobs.get(existingJobId);

        if (existingJob) {
          return { job: existingJob as JobRecord<T, R>, isExisting: true };
        }
      }
    }

    // 2. Capacity & Backpressure Check
    if (this.waitingQueue.length >= this.maxQueueCapacity) {
      throw new Error(
        `QUEUE_CAPACITY_EXCEEDED: High load backpressure active. Queue has reached max capacity (${this.maxQueueCapacity}).`
      );
    }

    // 3. Create Job Record
    const jobId = `es-job-${randomUUID()}`;
    const job: JobRecord<T, R> = {
      id: jobId,
      tenantId: params.tenantId,
      operation: params.operation,
      data: params.data,
      priority: params.priority ?? "normal",
      idempotencyKey: params.idempotencyKey,
      webhookUrl: params.webhookUrl,
      webhookSecret: params.webhookSecret,
      batchId: params.batchId,
      status: "queued",
      progress: 0,
      attempts: 0,
      maxRetries: params.maxRetries ?? this.defaultMaxRetries,
      timeoutMs: params.timeoutMs ?? this.defaultTimeoutMs,
      queuedAt: new Date(),
      errorsHistory: [],
    };

    if (params.idempotencyKey) {
      this.idempotencyIndex.set(`${params.tenantId}:${params.idempotencyKey}`, jobId);
    }

    // 4. Priority Insertion
    this.insertWithPriority(job as JobRecord);
    this.emit("job:queued", job);

    // 5. Trigger dispatch loop
    setImmediate(() => this.dispatch());

    return { job, isExisting: false };
  }

  public async enqueueBatch<T = unknown>(params: {
    tenantId: string;
    items: Array<{
      operation: OperationType;
      data: T;
      priority?: JobPriority;
      idempotencyKey?: string;
    }>;
    webhookUrl?: string;
    batchPriority?: JobPriority;
  }): Promise<BatchRecord> {
    const batchId = `es-batch-${randomUUID()}`;
    const jobIds: string[] = [];

    const batchRecord: BatchRecord = {
      batchId,
      tenantId: params.tenantId,
      total: params.items.length,
      jobIds,
      queued: params.items.length,
      processing: 0,
      completed: 0,
      failed: 0,
      status: "queued",
      webhookUrl: params.webhookUrl,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.batches.set(batchId, batchRecord);

    for (const item of params.items) {
      const { job } = await this.enqueue({
        tenantId: params.tenantId,
        operation: item.operation,
        data: item.data,
        priority: item.priority ?? params.batchPriority ?? "bulk",
        idempotencyKey: item.idempotencyKey,
        batchId,
      });
      jobIds.push(job.id);
    }

    this.emit("batch:queued", batchRecord);
    return batchRecord;
  }

  public getJob(jobId: string): JobRecord | undefined {
    return (
      this.activeJobs.get(jobId) ||
      this.completedJobs.get(jobId) ||
      this.waitingQueue.find((j) => j.id === jobId) ||
      this.failedJobs.get(jobId) ||
      this.deadLetterJobs.get(jobId)
    );
  }

  public getBatch(batchId: string): BatchRecord | undefined {
    return this.batches.get(batchId);
  }

  public pause(): void {
    this.isPaused = true;
    this.emit("queue:paused");
  }

  public resume(): void {
    this.isPaused = false;
    this.emit("queue:resumed");
    setImmediate(() => this.dispatch());
  }

  public getMetrics(): QueueMetrics {
    const now = Date.now();
    this.completedTimestamps = this.completedTimestamps.filter((t) => now - t <= 60000);
    const avgDuration =
      this.totalCompletedCount > 0
        ? Math.round(this.totalDurationMs / this.totalCompletedCount)
        : 0;

    return {
      waiting: this.waitingQueue.length,
      active: this.activeJobs.size,
      completed: this.completedJobs.size,
      failed: this.failedJobs.size,
      deadLetter: this.deadLetterJobs.size,
      throughputPerMinute: this.completedTimestamps.length,
      averageExecutionTimeMs: avgDuration,
      activeWorkers: this.activeJobs.size,
      maxConcurrency: this.concurrency,
      isPaused: this.isPaused,
    };
  }

  private insertWithPriority(job: JobRecord): void {
    const jobWeight = PRIORITY_WEIGHTS[job.priority] ?? 2;
    let insertIndex = this.waitingQueue.length;

    for (let i = 0; i < this.waitingQueue.length; i++) {
      const currentWeight = PRIORITY_WEIGHTS[this.waitingQueue[i].priority] ?? 2;
      if (jobWeight > currentWeight) {
        insertIndex = i;
        break;
      }
    }

    this.waitingQueue.splice(insertIndex, 0, job);
  }

  private async dispatch(): Promise<void> {
    if (this.isPaused) return;

    while (this.activeJobs.size < this.concurrency && this.waitingQueue.length > 0) {
      const job = this.waitingQueue.shift();
      if (!job) break;

      this.activeJobs.set(job.id, job);
      job.status = "processing";
      job.startedAt = new Date();
      job.attempts += 1;

      this.updateBatchStatus(job.batchId);
      this.emit("job:started", job);

      this.executeJob(job).catch((err) => {
        this.emit("queue:error", { jobId: job.id, error: err });
      });
    }
  }

  private async executeJob(job: JobRecord): Promise<void> {
    const handler = this.handlers.get(job.operation);

    if (!handler) {
      this.finalizeFailure(
        job,
        new Error(`NO_HANDLER_FOR_OPERATION: Operation '${job.operation}' has no registered handler.`)
      );
      return;
    }

    const progressUpdater = (percent: number) => {
      job.progress = Math.min(100, Math.max(0, percent));
      this.emit("job:progress", { jobId: job.id, progress: job.progress, status: job.status });
    };

    try {
      let timeoutHandle: NodeJS.Timeout;
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          reject(new Error(`JOB_TIMEOUT: Execution exceeded timeout of ${job.timeoutMs}ms.`));
        }, job.timeoutMs);
      });

      const executionPromise = handler(job, progressUpdater);
      const result = await Promise.race([executionPromise, timeoutPromise]);
      clearTimeout(timeoutHandle!);

      const completedAt = new Date();
      job.status = "completed";
      job.progress = 100;
      job.completedAt = completedAt;
      job.durationMs = completedAt.getTime() - (job.startedAt?.getTime() ?? completedAt.getTime());
      job.result = result;

      this.activeJobs.delete(job.id);
      this.completedJobs.set(job.id, job);

      this.totalCompletedCount += 1;
      this.totalDurationMs += job.durationMs;
      this.completedTimestamps.push(completedAt.getTime());

      this.updateBatchStatus(job.batchId);
      this.emit("job:completed", job);
    } catch (err) {
      const errorObj = err instanceof Error ? err : new Error(String(err));
      this.handleJobError(job, errorObj);
    } finally {
      setImmediate(() => this.dispatch());
    }
  }

  private handleJobError(job: JobRecord, error: Error): void {
    const errorRecord = {
      code: error.name || "JOB_EXECUTION_ERROR",
      message: error.message,
      details: (error as { details?: unknown }).details,
      attempt: job.attempts,
      timestamp: new Date().toISOString(),
    };

    job.error = errorRecord;
    job.errorsHistory.push(errorRecord);

    if (job.attempts < job.maxRetries) {
      const backoffDelay = Math.min(
        this.retryBaseDelayMs * Math.pow(2, job.attempts - 1),
        this.retryMaxDelayMs
      );

      job.status = "queued";
      this.activeJobs.delete(job.id);
      this.emit("job:retry", { jobId: job.id, attempt: job.attempts, delayMs: backoffDelay });

      setTimeout(() => {
        this.insertWithPriority(job);
        setImmediate(() => this.dispatch());
      }, backoffDelay);
    } else {
      this.finalizeFailure(job, error);
    }
  }

  private finalizeFailure(job: JobRecord, error: Error): void {
    const completedAt = new Date();
    job.status = "failed";
    job.completedAt = completedAt;
    job.durationMs = completedAt.getTime() - (job.startedAt?.getTime() ?? completedAt.getTime());

    this.activeJobs.delete(job.id);
    this.failedJobs.set(job.id, job);
    this.deadLetterJobs.set(job.id, job);

    this.updateBatchStatus(job.batchId);
    this.emit("job:failed", job);
    this.emit("job:dlq", job);
  }

  private updateBatchStatus(batchId?: string): void {
    if (!batchId) return;
    const batch = this.batches.get(batchId);
    if (!batch) return;

    let queued = 0;
    let processing = 0;
    let completed = 0;
    let failed = 0;

    for (const jobId of batch.jobIds) {
      const job = this.getJob(jobId);
      if (!job) continue;
      if (job.status === "queued") queued++;
      else if (job.status === "processing") processing++;
      else if (job.status === "completed") completed++;
      else if (job.status === "failed") failed++;
    }

    batch.queued = queued;
    batch.processing = processing;
    batch.completed = completed;
    batch.failed = failed;
    batch.updatedAt = new Date();

    if (queued === 0 && processing === 0) {
      batch.completedAt = new Date();
      if (failed === 0) batch.status = "completed";
      else if (completed > 0) batch.status = "partially_failed";
      else batch.status = "failed";

      this.emit("batch:completed", batch);
    } else {
      batch.status = "processing";
      this.emit("batch:progress", batch);
    }
  }
}
