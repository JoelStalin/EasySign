import { createHmac, randomUUID } from "node:crypto";
import type { JobRecord } from "../queue/types.js";

export interface WebhookDeliveryResult {
  deliveryId: string;
  statusCode?: number;
  success: boolean;
  attempt: number;
  durationMs: number;
  error?: string;
}

export class WebhookDispatcher {
  public async dispatchJobNotification(
    job: JobRecord,
    options: { maxRetries?: number } = {}
  ): Promise<WebhookDeliveryResult | null> {
    if (!job.webhookUrl) return null;

    const deliveryId = `wh-dlv-${randomUUID()}`;
    const timestamp = Date.now().toString();
    const payload = JSON.stringify({
      event: `transaction.${job.status}`,
      deliveryId,
      timestamp,
      job: {
        id: job.id,
        tenantId: job.tenantId,
        operation: job.operation,
        status: job.status,
        progress: job.progress,
        idempotencyKey: job.idempotencyKey,
        batchId: job.batchId,
        durationMs: job.durationMs,
        result: job.result,
        error: job.error,
        completedAt: job.completedAt?.toISOString(),
      },
    });

    const signature = job.webhookSecret
      ? createHmac("sha256", job.webhookSecret).update(`${timestamp}.${payload}`).digest("hex")
      : createHmac("sha256", "easysign-default-secret").update(`${timestamp}.${payload}`).digest("hex");

    const maxRetries = options.maxRetries ?? 3;
    let attempt = 0;
    let lastError: string | undefined;

    while (attempt < maxRetries) {
      attempt++;
      const startTime = Date.now();
      try {
        const response = await fetch(job.webhookUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "EasySign-Webhook-Dispatcher/1.0",
            "X-EasySign-Delivery-Id": deliveryId,
            "X-EasySign-Timestamp": timestamp,
            "X-EasySign-Signature": `t=${timestamp},v1=${signature}`,
          },
          body: payload,
          signal: AbortSignal.timeout(5000),
        });

        const durationMs = Date.now() - startTime;
        if (response.ok) {
          return {
            deliveryId,
            statusCode: response.status,
            success: true,
            attempt,
            durationMs,
          };
        } else {
          lastError = `HTTP_${response.status}: ${response.statusText}`;
        }
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      }

      if (attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 100 * Math.pow(2, attempt - 1)));
      }
    }

    return {
      deliveryId,
      success: false,
      attempt,
      durationMs: 0,
      error: lastError,
    };
  }
}
