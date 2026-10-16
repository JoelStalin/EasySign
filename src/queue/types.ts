export type JobPriority = "critical" | "high" | "normal" | "bulk";

export type JobStatus = "queued" | "processing" | "completed" | "failed" | "cancelled";

export type OperationType =
  | "sign_ecf_xml"
  | "sign_pdf"
  | "verify_signature"
  | "batch_sign_item";

export interface JobPayload<T = unknown> {
  id: string;
  tenantId: string;
  operation: OperationType;
  data: T;
  priority: JobPriority;
  idempotencyKey?: string;
  webhookUrl?: string;
  webhookSecret?: string;
  maxRetries?: number;
  timeoutMs?: number;
  createdAt: Date;
  batchId?: string;
}

export interface JobError {
  code: string;
  message: string;
  details?: unknown;
  attempt: number;
  timestamp: string;
}

export interface JobRecord<T = unknown, R = unknown> {
  id: string;
  tenantId: string;
  operation: OperationType;
  data: T;
  priority: JobPriority;
  idempotencyKey?: string;
  webhookUrl?: string;
  webhookSecret?: string;
  batchId?: string;
  status: JobStatus;
  progress: number; // 0 to 100
  attempts: number;
  maxRetries: number;
  timeoutMs: number;
  queuedAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  durationMs?: number;
  result?: R;
  error?: JobError;
  errorsHistory: JobError[];
}

export interface BatchRecord {
  batchId: string;
  tenantId: string;
  total: number;
  jobIds: string[];
  queued: number;
  processing: number;
  completed: number;
  failed: number;
  status: "queued" | "processing" | "completed" | "partially_failed" | "failed";
  webhookUrl?: string;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
}

export interface QueueMetrics {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  deadLetter: number;
  throughputPerMinute: number;
  averageExecutionTimeMs: number;
  activeWorkers: number;
  maxConcurrency: number;
  isPaused: boolean;
}

export interface QueueOptions {
  concurrency?: number;
  maxQueueCapacity?: number;
  defaultMaxRetries?: number;
  defaultTimeoutMs?: number;
  retryBaseDelayMs?: number;
  retryMaxDelayMs?: number;
}
