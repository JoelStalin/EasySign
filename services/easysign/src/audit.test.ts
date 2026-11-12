import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditError, AuditLog, redact } from "./services/audit-log.js";
import { buildApp } from "./app.js";

const ev = (over: Record<string, unknown> = {}) => ({ correlationId: "corr-00000001", tenantId: "t1", actor: "a", action: "x", resource: "/r", outcome: "success" as const, ...over });

test("events are chained, queryable and tampering is detected on reload", () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-audit-")), "audit.jsonl");
  const a = new AuditLog({ filePath: file });
  a.record(ev());
  a.record(ev({ tenantId: "t2", action: "y" }));
  assert.equal(a.verifyChain(), true);
  assert.equal(a.query({ tenantId: "t2" }).length, 1);
  assert.equal(new AuditLog({ filePath: file }).query().length, 2);
  writeFileSync(file, readFileSync(file, "utf8").replace('"t2"', '"t9"'));
  assert.throws(() => new AuditLog({ filePath: file }), (e: unknown) => e instanceof AuditError && e.code === "CHAIN_BROKEN");
});

test("secrets are redacted and long values truncated before storage", () => {
  const out = redact({ user: "u", passphrase: "hunter2", nested: { apiKey: "k", ok: "fine" }, list: [{ token: "t" }], big: "x".repeat(900) }) as Record<string, any>;
  assert.equal(out.passphrase, "[REDACTED]");
  assert.equal(out.nested.apiKey, "[REDACTED]");
  assert.equal(out.nested.ok, "fine");
  assert.equal(out.list[0].token, "[REDACTED]");
  assert.ok(out.big.endsWith("[TRUNCATED]"));
  const log = new AuditLog();
  const e = log.record(ev({ details: { password: "p" } }));
  assert.equal((e.details as any).password, "[REDACTED]");
  assert.throws(() => log.record(ev({ correlationId: "" })), AuditError);
});

test("evidence export is per tenant, anchored to the ledger head and reports chain validity", () => {
  const log = new AuditLog();
  log.record(ev());
  const last = log.record(ev({ tenantId: "t2" }));
  const pkg = log.exportEvidence("t1");
  assert.equal(pkg.eventCount, 1);
  assert.equal(pkg.headHash, last.hash);
  assert.equal(pkg.chainValid, true);
});

test("API: every response carries a correlation ID; denied and successful writes are audited without bodies", async () => {
  const audit = new AuditLog();
  const app = buildApp({ registryAdminToken: "tok", auditLog: audit });
  const r = await app.inject({ method: "GET", url: "/v1/system/status", headers: { "x-correlation-id": "my-correlation-1" } });
  assert.equal(r.headers["x-correlation-id"], "my-correlation-1");
  assert.match(String((await app.inject({ method: "GET", url: "/v1/system/status", headers: { "x-correlation-id": "bad id!" } })).headers["x-correlation-id"]), /^[0-9a-f-]{36}$/);

  const cert = { serial: "AB12", subject: "CN=a", issuer: "CN=b", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z" };
  await app.inject({ method: "POST", url: "/v1/registry/certificates", headers: { authorization: "Bearer wrong" }, payload: cert });
  await app.inject({ method: "POST", url: "/v1/registry/certificates", headers: { authorization: "Bearer tok", "x-correlation-id": "corr-register-1" }, payload: cert });
  const events = audit.query();
  assert.deepEqual(events.map((e) => e.outcome), ["denied", "success"]);
  assert.equal(events[1].correlationId, "corr-register-1");
  assert.equal(events[0].actor, "anonymous");
  assert.ok(!JSON.stringify(events).includes("CN=a"), "request bodies are not stored");
  assert.equal(audit.verifyChain(), true);
});

test("API: reading and exporting the ledger needs the admin token and fails closed", async () => {
  const noTok = buildApp({ registryAdminToken: undefined, auditLog: new AuditLog() });
  assert.equal((await noTok.inject({ method: "GET", url: "/v1/audit/events" })).statusCode, 503);
  const app = buildApp({ registryAdminToken: "tok", auditLog: new AuditLog() });
  assert.equal((await app.inject({ method: "GET", url: "/v1/audit/events" })).statusCode, 401);
  const h = { authorization: "Bearer tok" };
  assert.equal((await app.inject({ method: "POST", url: "/v1/audit/export", headers: h, payload: {} })).statusCode, 400);
  const ok = await app.inject({ method: "POST", url: "/v1/audit/export", headers: h, payload: { tenantId: "platform" } });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().chainValid, true);
  assert.equal((await app.inject({ method: "GET", url: "/v1/audit/events?tenantId=platform", headers: h })).json().chainValid, true);
});
