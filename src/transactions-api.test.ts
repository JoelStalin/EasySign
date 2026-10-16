import test from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './app.js';
import { EasySignClient } from './client/easysign-client.js';

test('API: POST /v1/transactions/async returns 202 Accepted and executes asynchronously', async () => {
  const app = buildApp({ queueConcurrency: 5 });

  const response = await app.inject({
    method: 'POST',
    url: '/v1/transactions/async',
    payload: {
      tenantId: 'tenant-test-1',
      operation: 'sign_ecf_xml',
      data: {
        rncEmisor: '131234567',
        eNcf: 'E3100000001',
        amountTotal: 25000.0,
      },
      priority: 'high',
      idempotencyKey: 'idem-tx-001',
    },
  });

  assert.equal(response.statusCode, 202);
  const body = response.json();
  assert.ok(body.jobId);
  assert.equal(body.status, 'queued');
  assert.ok(body.trackingUrl);
  assert.ok(body.streamUrl);

  // Poll for completion
  let finalJob: any;
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 20));
    const checkRes = await app.inject({
      method: 'GET',
      url: `/v1/jobs/${body.jobId}`,
    });
    finalJob = checkRes.json();
    if (finalJob.status === 'completed') break;
  }

  assert.equal(finalJob.status, 'completed');
  assert.ok(finalJob.result);
  assert.equal(finalJob.result.eNcf, 'E3100000001');
  assert.ok(finalJob.result.signedXml.includes('<Signature'));
  assert.ok(finalJob.result.securityCode);
  assert.equal(finalJob.result.securityCode.length, 6);

  await app.close();
});

test('API: POST /v1/transactions/batch handles bulk e-CF signing', async () => {
  const app = buildApp({ queueConcurrency: 10 });

  const items = Array.from({ length: 15 }, (_, i) => ({
    operation: 'sign_ecf_xml',
    data: {
      rncEmisor: '131234567',
      eNcf: `E31000000${String(i + 1).padStart(2, '0')}`,
      amountTotal: 1000.0 * (i + 1),
    },
    priority: 'bulk',
    idempotencyKey: `bulk-item-${i}`,
  }));

  const response = await app.inject({
    method: 'POST',
    url: '/v1/transactions/batch',
    payload: {
      tenantId: 'tenant-test-batch',
      items,
    },
  });

  assert.equal(response.statusCode, 202);
  const body = response.json();
  assert.ok(body.batchId);
  assert.equal(body.total, 15);

  // Wait for batch to process
  let finalBatch: any;
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 30));
    const batchRes = await app.inject({
      method: 'GET',
      url: `/v1/batches/${body.batchId}`,
    });
    finalBatch = batchRes.json();
    if (finalBatch.status === 'completed') break;
  }

  assert.equal(finalBatch.status, 'completed');
  assert.equal(finalBatch.completed, 15);
  assert.equal(finalBatch.failed, 0);

  // Check queue metrics
  const metricsRes = await app.inject({ method: 'GET', url: '/v1/queue/metrics' });
  const metrics = metricsRes.json();
  assert.ok(metrics.completed >= 15);

  await app.close();
});

test('API: GET /v1/queue/metrics and Pause/Resume lifecycle', async () => {
  const app = buildApp();

  const pauseRes = await app.inject({ method: 'POST', url: '/v1/queue/pause' });
  assert.equal(pauseRes.statusCode, 200);

  const metricsRes = await app.inject({ method: 'GET', url: '/v1/queue/metrics' });
  assert.equal(metricsRes.json().isPaused, true);

  const resumeRes = await app.inject({ method: 'POST', url: '/v1/queue/resume' });
  assert.equal(resumeRes.statusCode, 200);

  const metricsRes2 = await app.inject({ method: 'GET', url: '/v1/queue/metrics' });
  assert.equal(metricsRes2.json().isPaused, false);

  await app.close();
});
