import { existsSync, mkdirSync, readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { JobRecord } from "./types.js";

export interface JournalStorageOptions {
  filePath?: string;
  enabled?: boolean;
}

export class JournalStorage {
  private readonly filePath: string;
  private readonly enabled: boolean;

  constructor(options: JournalStorageOptions = {}) {
    this.filePath = options.filePath ?? "./data/easysign_journal.jsonl";
    this.enabled = options.enabled ?? true;

    if (this.enabled) {
      const dir = dirname(this.filePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  public recordJobEvent(event: "queued" | "started" | "completed" | "failed", job: JobRecord): void {
    if (!this.enabled) return;

    try {
      const entry = JSON.stringify({
        event,
        timestamp: new Date().toISOString(),
        jobId: job.id,
        tenantId: job.tenantId,
        operation: job.operation,
        data: job.data,
        priority: job.priority,
        idempotencyKey: job.idempotencyKey,
        batchId: job.batchId,
        webhookUrl: job.webhookUrl,
        webhookSecret: job.webhookSecret,
        status: job.status,
        progress: job.progress,
        attempts: job.attempts,
        maxRetries: job.maxRetries,
        timeoutMs: job.timeoutMs,
        result: job.result,
        error: job.error,
      }) + "\n";

      appendFileSync(this.filePath, entry, "utf-8");
    } catch {
      // Non-fatal logging
    }
  }

  public recoverIncompleteJobs(): JobRecord[] {
    if (!this.enabled || !existsSync(this.filePath)) {
      return [];
    }

    try {
      const content = readFileSync(this.filePath, "utf-8");
      const lines = content.split("\n").filter((l) => l.trim().length > 0);
      const jobsMap = new Map<string, JobRecord>();

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const { event, ...jobData } = entry;

          const job: JobRecord = {
            id: jobData.jobId,
            tenantId: jobData.tenantId,
            operation: jobData.operation,
            data: jobData.data,
            priority: jobData.priority,
            idempotencyKey: jobData.idempotencyKey,
            batchId: jobData.batchId,
            webhookUrl: jobData.webhookUrl,
            webhookSecret: jobData.webhookSecret,
            status: jobData.status,
            progress: jobData.progress,
            attempts: jobData.attempts ?? 0,
            maxRetries: jobData.maxRetries ?? 3,
            timeoutMs: jobData.timeoutMs ?? 30000,
            queuedAt: new Date(jobData.timestamp ?? Date.now()),
            result: jobData.result,
            error: jobData.error,
            errorsHistory: [],
          };

          jobsMap.set(job.id, job);
        } catch {
          // Skip corrupted line
        }
      }

      // Recover only jobs that were not completed or failed before the crash
      const incompleteJobs: JobRecord[] = [];
      for (const job of jobsMap.values()) {
        if (job.status === "queued" || job.status === "processing") {
          job.status = "queued"; // Reset processing to queued for safe re-execution
          incompleteJobs.push(job);
        }
      }

      return incompleteJobs;
    } catch {
      return [];
    }
  }

  public clear(): void {
    if (this.enabled && existsSync(this.filePath)) {
      try {
        writeFileSync(this.filePath, "", "utf-8");
      } catch {
        // Ignore
      }
    }
  }
}
