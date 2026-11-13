import test from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './app.js';

test('reports sandbox status', async () => {
 const app = buildApp();
 const response = await app.inject({ method: 'GET', url: '/v1/system/status' });
 assert.equal(response.statusCode, 200);
 assert.equal(response.json().accredited, false);
 await app.close();
});

test('does not permit unsigned or unauthenticated signing', async () => {
 const app = buildApp();
 const response = await app.inject({ method: 'POST', url: '/v1/signature-requests', payload: { tenantId: 'not-valid' } });
 assert.equal(response.statusCode, 400);
 await app.close();
});
