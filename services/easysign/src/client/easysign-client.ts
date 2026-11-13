export interface EasySignClientOptions {
  baseUrl: string;
  tenantId: string;
  apiKey?: string;
  timeoutMs?: number;
}

export interface AsyncSigningResponse {
  jobId: string;
  status: string;
  isIdempotentReplay?: boolean;
  priority: string;
  trackingUrl: string;
  streamUrl: string;
  idempotencyKey?: string;
  queuePosition: number;
  estimatedWaitMs: number;
}

export class EasySignClient {
  private readonly baseUrl: string;
  private readonly tenantId: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(options: EasySignClientOptions) {
    this.baseUrl = options.baseUrl.endsWith("/") ? options.baseUrl.slice(0, -1) : options.baseUrl;
    this.tenantId = options.tenantId;
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 30000;
  }

  public async submitAsync(params: {
    operation: "sign_ecf_xml" | "sign_pdf" | "verify_signature" | "batch_sign_item";
    data: Record<string, unknown>;
    priority?: "critical" | "high" | "normal" | "bulk";
    idempotencyKey?: string;
    webhookUrl?: string;
  }): Promise<AsyncSigningResponse> {
    const url = `${this.baseUrl}/v1/transactions/async`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Tenant-Id": this.tenantId,
    };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;
    if (params.idempotencyKey) headers["Idempotency-Key"] = params.idempotencyKey;

    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        tenantId: this.tenantId,
        operation: params.operation,
        data: params.data,
        priority: params.priority ?? "normal",
        idempotencyKey: params.idempotencyKey,
        webhookUrl: params.webhookUrl,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!res.ok) {
      const errorBody = await res.text();
      throw new Error(`EASYSIGN_API_ERROR (${res.status}): ${errorBody}`);
    }

    return (await res.json()) as AsyncSigningResponse;
  }

  public async submitAndWait<R = unknown>(
    params: {
      operation: "sign_ecf_xml" | "sign_pdf" | "verify_signature" | "batch_sign_item";
      data: Record<string, unknown>;
      priority?: "critical" | "high" | "normal" | "bulk";
      idempotencyKey?: string;
    },
    options: {
      pollingIntervalMs?: number;
      maxWaitMs?: number;
      onProgress?: (percent: number) => void;
    } = {}
  ): Promise<R> {
    const initial = await this.submitAsync(params);
    const pollingInterval = options.pollingIntervalMs ?? 100;
    const maxWait = options.maxWaitMs ?? 30000;
    const startTime = Date.now();

    while (Date.now() - startTime < maxWait) {
      await new Promise((resolve) => setTimeout(resolve, pollingInterval));

      const statusRes = await fetch(`${this.baseUrl}/v1/jobs/${initial.jobId}`, {
        headers: this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {},
      });

      if (!statusRes.ok) {
        throw new Error(`FAILED_POLLING_JOB: HTTP ${statusRes.status}`);
      }

      const jobData = (await statusRes.json()) as {
        status: string;
        progress: number;
        result?: R;
        error?: { message: string };
      };

      options.onProgress?.(jobData.progress);

      if (jobData.status === "completed") {
        return jobData.result as R;
      }

      if (jobData.status === "failed") {
        throw new Error(`JOB_EXECUTION_FAILED: ${jobData.error?.message ?? "Unknown error"}`);
      }
    }

    throw new Error(`WAIT_TIMEOUT: Job '${initial.jobId}' did not complete within ${maxWait}ms.`);
  }

  public async submitBatch(params: {
    items: Array<{
      operation: "sign_ecf_xml" | "sign_pdf" | "verify_signature" | "batch_sign_item";
      data: Record<string, unknown>;
      priority?: "critical" | "high" | "normal" | "bulk";
      idempotencyKey?: string;
    }>;
    webhookUrl?: string;
    batchPriority?: "critical" | "high" | "normal" | "bulk";
  }): Promise<{ batchId: string; total: number; status: string; trackingUrl: string }> {
    const url = `${this.baseUrl}/v1/transactions/batch`;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;

    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        tenantId: this.tenantId,
        items: params.items,
        webhookUrl: params.webhookUrl,
        batchPriority: params.batchPriority,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!res.ok) {
      const errorBody = await res.text();
      throw new Error(`EASYSIGN_BATCH_ERROR (${res.status}): ${errorBody}`);
    }

    return (await res.json()) as { batchId: string; total: number; status: string; trackingUrl: string };
  }

  public async getQueueMetrics(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/v1/queue/metrics`);
    return (await res.json()) as Record<string, unknown>;
  }
}
