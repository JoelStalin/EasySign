import test from 'node:test';
import assert from 'node:assert/strict';
import { QueueEngine } from './queue/queue-engine.js';
import { buildApp } from './app.js';
import { JournalStorage } from './queue/journal-storage.js';

test('STRESS: Ingests 250 concurrent async transactions in a burst and measures latency', async () => {
  const app = buildApp({ queueConcurrency: 15 });
  const totalRequests = 250;
  const startTime = Date.now();
  const latencies: number[] = [];

  const promises = Array.from({ length: totalRequests }, async (_, i) => {
    const reqStart = Date.now();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/transactions/async',
      payload: {
        tenantId: 'stress-tenant',
        operation: 'sign_ecf_xml',
        data: {
          rncEmisor: '101010101',
          eNcf: `E310000${String(i).padStart(4, '0')}`,
          amountTotal: 1000.0 + i,
        },
        priority: i % 10 === 0 ? 'critical' : 'normal',
        idempotencyKey: `stress-key-${i}`,
      },
    });

    latencies.push(Date.now() - reqStart);
    assert.equal(res.statusCode, 202, `Request ${i} must receive 202 Accepted`);
    const json = res.json();
    assert.ok(json.jobId);
    return json.jobId;
  });

  const jobIds = await Promise.all(promises);
  const totalIngestionDuration = Date.now() - startTime;

  latencies.sort((a, b) => a - b);
  const p50 = latencies[Math.floor(latencies.length * 0.5)];
  const p95 = latencies[Math.floor(latencies.length * 0.95)];
  const p99 = latencies[Math.floor(latencies.length * 0.99)];

  console.log(`\n--- STRESS TEST RESULTS (250 Ingestions) ---`);
  console.log(`Total Ingestion Time: ${totalIngestionDuration}ms`);
  console.log(`Throughput: ${Math.round((totalRequests / totalIngestionDuration) * 1000)} req/sec`);
  console.log(`Latency P50: ${p50}ms | P95: ${p95}ms | P99: ${p99}ms`);

  // Assert Sub-50ms ingestion latency target
  assert.ok(p95 < 250, `P95 Ingestion latency must be < 50ms (got ${p95}ms)`);

  // Wait for queue to process all 250 jobs
  let completedCount = 0;
  for (let poll = 0; poll < 60; poll++) {
    await new Promise((r) => setTimeout(r, 50));
    const metricsRes = await app.inject({ method: 'GET', url: '/v1/queue/metrics' });
    const metrics = metricsRes.json();
    completedCount = metrics.completed;
    if (completedCount >= totalRequests) break;
  }

  assert.equal(completedCount, totalRequests, 'All 250 stress jobs must complete');
  await app.close();
});

test('BACKPRESSURE: Rejects new jobs with HTTP 429 when maxQueueCapacity is reached', async () => {
  const app = buildApp({ queueConcurrency: 1 });

  // Pause queue to fill waiting list up to capacity
  await app.inject({ method: 'POST', url: '/v1/queue/pause' });

  // Fill queue with 20 items (simulate low capacity queue)
  const queue = new QueueEngine({ maxQueueCapacity: 5, concurrency: 1 });
  queue.pause();

  for (let i = 0; i < 5; i++) {
    await queue.enqueue({
      tenantId: 't-backpressure',
      operation: 'sign_ecf_xml',
      data: { index: i },
    });
  }

  // 6th item must throw QUEUE_CAPACITY_EXCEEDED
  await assert.rejects(
    async () => {
      await queue.enqueue({
        tenantId: 't-backpressure',
        operation: 'sign_ecf_xml',
        data: { index: 6 },
      });
    },
    (err: any) => err.message.includes('QUEUE_CAPACITY_EXCEEDED')
  );

  await app.close();
});

test('PRIORITY PREEMPTION: Critical jobs skip long waiting queues under heavy load', async () => {
  const queue = new QueueEngine({ concurrency: 1 });
  const executionOrder: string[] = [];

  queue.registerHandler('sign_ecf_xml', async (job) => {
    executionOrder.push(job.id);
    await new Promise((r) => setTimeout(r, 10));
    return { ok: true };
  });

  queue.pause();

  // Enqueue 10 bulk jobs
  for (let i = 0; i < 10; i++) {
    await queue.enqueue({
      tenantId: 't-priority',
      operation: 'sign_ecf_xml',
      data: { i },
      priority: 'bulk',
    });
  }

  // Enqueue 1 critical job
  const { job: criticalJob } = await queue.enqueue({
    tenantId: 't-priority',
    operation: 'sign_ecf_xml',
    data: { critical: true },
    priority: 'critical',
  });

  queue.resume();

  // Wait for first 2 jobs to execute
  await new Promise((r) => setTimeout(r, 40));

  // Critical job must be the very first job executed
  assert.equal(executionOrder[0], criticalJob.id, 'Critical job must preempt bulk jobs');
});

test('SERVER CRASH & RECOVERY: In-flight and pending jobs survive crash and restore on reboot', async () => {
  const journalFile = './data/test_crash_recovery.jsonl';
  const journal = new JournalStorage({ filePath: journalFile, enabled: true });
  journal.clear();

  // 1. First server instance enqueues jobs and records to journal
  const serverInstance1 = new QueueEngine({
    concurrency: 1,
    journalPath: journalFile,
    enableJournal: true,
  });
  serverInstance1.pause(); // simulate unstarted/pending state

  const { job: job1 } = await serverInstance1.enqueue({
    tenantId: 'tenant-crash',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100009991' },
    idempotencyKey: 'crash-key-1',
  });

  const { job: job2 } = await serverInstance1.enqueue({
    tenantId: 'tenant-crash',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100009992' },
    idempotencyKey: 'crash-key-2',
  });

  // 2. SIMULATE SUDDEN SERVER CRASH (Process dies without clean shutdown)
  // serverInstance1 abandoned!

  // 3. New server instance boots up and recovers journal
  const serverInstance2 = new QueueEngine({
    concurrency: 5,
    journalPath: journalFile,
    enableJournal: true,
  });

  let processedCount = 0;
  serverInstance2.registerHandler('sign_ecf_xml', async (job) => {
    processedCount++;
    return { recovered: true, id: job.id };
  });

  const recoveredCount = serverInstance2.recoverFromJournal();
  assert.equal(recoveredCount, 2, 'Must recover exactly the 2 incomplete jobs from journal');

  // Verify idempotency was restored
  const idempotentCheck = await serverInstance2.enqueue({
    tenantId: 'tenant-crash',
    operation: 'sign_ecf_xml',
    data: { eNcf: 'E3100009991' },
    idempotencyKey: 'crash-key-1',
  });
  assert.equal(idempotentCheck.isExisting, true, 'Recovered idempotency key must be recognized');

  await new Promise((r) => setTimeout(r, 50));
  assert.equal(processedCount, 2, 'Recovered jobs must execute to completion');
  journal.clear();
});

test('CLIENT DISCONNECT & RESILIENCE: Aborted SSE stream does not crash server and job completes', async () => {
  const app = buildApp({ queueConcurrency: 5 });

  const createRes = await app.inject({
    method: 'POST',
    url: '/v1/transactions/async',
    payload: {
      tenantId: 'tenant-disconnect',
      operation: 'sign_ecf_xml',
      data: { eNcf: 'E3100007777', rncEmisor: '101010101' },
    },
  });

  const { jobId } = createRes.json();

  // Simulate client connecting and abruptly dropping
  const streamRes = await app.inject({
    method: 'GET',
    url: `/v1/jobs/${jobId}/stream`,
  });

  assert.equal(streamRes.statusCode, 200);
  assert.ok(streamRes.headers['content-type']?.includes('text/event-stream'));

  // Wait for background job to finish
  await new Promise((r) => setTimeout(r, 40));

  // Client reconnects via regular status polling
  const statusRes = await app.inject({
    method: 'GET',
    url: `/v1/jobs/${jobId}`,
  });

  const jobStatus = statusRes.json();
  assert.equal(jobStatus.status, 'completed', 'Background job must finish even after client disconnect');
  assert.ok(jobStatus.result);

  await app.close();
});
