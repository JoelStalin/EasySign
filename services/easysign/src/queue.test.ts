import test from 'node:test';
import assert from 'node:assert/strict';
import { QueueEngine } from './queue/queue-engine.js';

test('QueueEngine: processes jobs and handles priority execution', async () => {
  const queue = new QueueEngine({ concurrency: 2 });
  const executionOrder: string[] = [];

  queue.registerHandler('sign_ecf_xml', async (job, updateProgress) => {
    executionOrder.push(job.id);
    updateProgress(50);
    await new Promise((r) => setTimeout(r, 20));
    updateProgress(100);
    return { signed: true, id: job.id };
  });

  // Pause to enqueue items before worker starts
  queue.pause();

  const { job: jobLow } = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000001' },
    priority: 'bulk',
  });

  const { job: jobCritical } = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000002' },
    priority: 'critical',
  });

  const { job: jobNormal } = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000003' },
    priority: 'normal',
  });

  // Resume queue
  queue.resume();

  // Wait for completion
  await new Promise((r) => setTimeout(r, 120));

  assert.equal(queue.getJob(jobCritical.id)?.status, 'completed');
  assert.equal(queue.getJob(jobNormal.id)?.status, 'completed');
  assert.equal(queue.getJob(jobLow.id)?.status, 'completed');

  // Critical must execute before bulk/normal
  assert.equal(executionOrder[0], jobCritical.id);
});

test('QueueEngine: enforces idempotency with identical key', async () => {
  const queue = new QueueEngine({ concurrency: 5 });
  let executionCount = 0;

  queue.registerHandler('sign_ecf_xml', async () => {
    executionCount++;
    return { signed: true };
  });

  const first = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000010' },
    idempotencyKey: 'idem-key-12345',
  });

  const second = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000010' },
    idempotencyKey: 'idem-key-12345',
  });

  assert.equal(first.job.id, second.job.id);
  assert.equal(first.isExisting, false);
  assert.equal(second.isExisting, true);

  await new Promise((r) => setTimeout(r, 60));
  assert.equal(executionCount, 1);
});

test('QueueEngine: retries failed jobs with backoff and sends to DLQ on max retries', async () => {
  const queue = new QueueEngine({
    concurrency: 5,
    defaultMaxRetries: 2,
    retryBaseDelayMs: 20,
    retryMaxDelayMs: 50,
  });

  let attempts = 0;
  queue.registerHandler('sign_ecf_xml', async () => {
    attempts++;
    throw new Error('SIMULATED_HSM_DOWN');
  });

  const { job } = await queue.enqueue({
    tenantId: 'tenant-1',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100000099' },
    maxRetries: 2,
  });

  await new Promise((r) => setTimeout(r, 150));

  const finalJob = queue.getJob(job.id);
  assert.equal(finalJob?.status, 'failed');
  assert.equal(finalJob?.attempts, 2);
  assert.equal(attempts, 2);

  const metrics = queue.getMetrics();
  assert.equal(metrics.deadLetter, 1);
  assert.equal(metrics.failed, 1);
});

test('QueueEngine: manages batch transactions and aggregate status', async () => {
  const queue = new QueueEngine({ concurrency: 5 });

  queue.registerHandler('batch_sign_item', async (job) => {
    await new Promise((r) => setTimeout(r, 10));
    return { signed: true, item: job.id };
  });

  const batch = await queue.enqueueBatch({
    tenantId: 'tenant-corp',
    items: [
      { operation: 'batch_sign_item', data: { index: 1 } },
      { operation: 'batch_sign_item', data: { index: 2 } },
      { operation: 'batch_sign_item', data: { index: 3 } },
      { operation: 'batch_sign_item', data: { index: 4 } },
      { operation: 'batch_sign_item', data: { index: 5 } },
    ],
  });

  assert.equal(batch.total, 5);
  assert.equal(batch.jobIds.length, 5);

  await new Promise((r) => setTimeout(r, 150));

  const updatedBatch = queue.getBatch(batch.batchId);
  assert.equal(updatedBatch?.status, 'completed');
  assert.equal(updatedBatch?.completed, 5);
  assert.equal(updatedBatch?.failed, 0);
});
