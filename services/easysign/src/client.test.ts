import test from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './app.js';
import { EasySignClient } from './client/easysign-client.js';

test('EasySignClient: submits async transaction and waits for result with submitAndWait', async () => {
  const app = buildApp({ queueConcurrency: 5 });
  const address = await app.listen({ port: 0, host: '127.0.0.1' });
  const port = (app.server.address() as any).port;

  const client = new EasySignClient({
    baseUrl: `http://127.0.0.1:${port}`,
    tenantId: 'tenant-easycount-test',
  });

  const progressTicks: number[] = [];
  const result = await client.submitAndWait<any>(
    {
      operation: 'sign_ecf_xml',
      data: {
        rncEmisor: '101010101',
        eNcf: 'E3100000005',
        amountTotal: 150000.0,
      },
      priority: 'high',
      idempotencyKey: 'client-idem-test-01',
    },
    {
      pollingIntervalMs: 25,
      onProgress: (p) => progressTicks.push(p),
    }
  );

  assert.ok(result);
  assert.equal(result.eNcf, 'E3100000005');
  assert.ok(result.signedXml.includes('<Signature'));
  assert.equal(result.securityCode.length, 6);
  assert.ok(progressTicks.length > 0);

  // Test batch submission
  const batchRes = await client.submitBatch({
    items: [
      { operation: 'sign_ecf_xml', data: { eNcf: 'E3200000001', rncEmisor: '101010101' } },
      { operation: 'sign_ecf_xml', data: { eNcf: 'E3200000002', rncEmisor: '101010101' } },
    ],
  });

  assert.ok(batchRes.batchId);
  assert.equal(batchRes.total, 2);

  // Test metrics
  const metrics = await client.getQueueMetrics();
  assert.ok(metrics.completed !== undefined);

  await app.close();
});
