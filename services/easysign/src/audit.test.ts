import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AUDIT_LEDGER, AuditError, AuditLog, redact, type AuditPayload } from "./services/audit-log.js";
import { GENESIS, type LedgerStore } from "./storage/ledger-store.js";
import { buildApp } from "./app.js";

const ev = (over: Record<string, unknown> = {}) => ({ correlationId: "corr-00000001", tenantId: "t1", actor: "a", action: "x", resource: "/r", outcome: "success" as const, ...over });

test("events are chained, queryable and tampering is detected on reload", async () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-audit-")), "audit.jsonl");
  const a = new AuditLog({ filePath: file });
  await a.record(ev());
  await a.record(ev({ tenantId: "t2", action: "y" }));
  assert.equal(await a.verifyChain(), true);
  assert.equal((await a.query({ tenantId: "t2" })).length, 1);
  assert.equal((await new AuditLog({ filePath: file }).query()).length, 2);
  writeFileSync(file, readFileSync(file, "utf8").replace('"t2"', '"t9"'));
  assert.throws(() => new AuditLog({ filePath: file }), (e: unknown) => e instanceof AuditError && e.code === "CHAIN_BROKEN");
});

test("secrets are redacted and long values truncated before storage", async () => {
  const out = redact({ user: "u", passphrase: "hunter2", nested: { apiKey: "k", ok: "fine" }, list: [{ token: "t" }], big: "x".repeat(900) }) as Record<string, any>;
  assert.equal(out.passphrase, "[REDACTED]");
  assert.equal(out.nested.apiKey, "[REDACTED]");
  assert.equal(out.nested.ok, "fine");
  assert.equal(out.list[0].token, "[REDACTED]");
  assert.ok(out.big.endsWith("[TRUNCATED]"));
  const log = new AuditLog();
  const e = await log.record(ev({ details: { password: "p" } }));
  assert.equal((e.details as any).password, "[REDACTED]");
  await assert.rejects(() => log.record(ev({ correlationId: "" })), AuditError);
});

test("evidence export is per tenant, anchored to the ledger head and reports chain validity", async () => {
  const log = new AuditLog();
  await log.record(ev());
  const last = await log.record(ev({ tenantId: "t2" }));
  const pkg = await log.exportEvidence("t1");
  assert.equal(pkg.eventCount, 1);
  assert.equal(pkg.headHash, last.hash);
  assert.equal(pkg.chainValid, true);
});

test("audit files written before LedgerStore still load, and new lines keep the original fields", async () => {
  // A line exactly as the previous implementation wrote it (no `type` field, same hash formula).
  const core = { seq: 1, at: "2026-11-01T10:00:00.000Z", correlationId: "corr-legacy-1", tenantId: "t1", actor: "alice", action: "POST /v1/consents", resource: "/v1/consents", outcome: "success", details: { statusCode: 201, targetTenant: "t1" }, prevHash: GENESIS };
  const hash = createHash("sha256").update(JSON.stringify([core.seq, core.at, core.correlationId, core.tenantId, core.actor, core.action, core.resource, core.outcome, core.details, core.prevHash])).digest("hex");
  const file = join(mkdtempSync(join(tmpdir(), "easysign-audit-")), "audit.jsonl");
  writeFileSync(file, JSON.stringify({ ...core, hash }) + "\n");

  const log = new AuditLog({ filePath: file });
  assert.deepEqual(await log.query(), [{ ...core, hash }]);
  const next = await log.record(ev());
  assert.equal(next.seq, 2);
  assert.equal(next.prevHash, hash);
  const written = JSON.parse(readFileSync(file, "utf8").split("\n").filter(Boolean)[1]) as Record<string, unknown>;
  assert.deepEqual(Object.keys(written).sort(), Object.keys(core).concat("hash").sort(), "no extra fields in the file");
  assert.deepEqual(written, next);
  assert.equal(await new AuditLog({ filePath: file }).verifyChain(), true);
});

test("the audit hash survives a jsonb round trip of arbitrary details", () => {
  const stored = AUDIT_LEDGER.canonical({ correlationId: "c", actor: "a", action: "x", resource: "/r", outcome: "success", details: { zeta: 1, alpha: { nested: [{ b: 2, a: "nul\u0000char" }], c: null }, mid: "ok" } });
  assert.deepEqual(Object.keys(stored.details), ["alpha", "mid", "zeta"]);
  assert.equal(JSON.stringify(stored.details), '{"alpha":{"c":null,"nested":[{"a":"nulchar","b":2}]},"mid":"ok","zeta":1}');
  const core = { seq: 3, type: "audit", at: "2026-11-12T10:00:00.000Z", tenantId: "t1", payload: stored, prevHash: GENESIS };
  // jsonb gives the keys back in its own order (by length, then alphabetically)
  const fromJsonb = { actor: "a", action: "x", details: { mid: "ok", zeta: 1, alpha: { c: null, nested: [{ a: "nulchar", b: 2 }] } }, outcome: "success", resource: "/r", correlationId: "c" };
  assert.equal(AUDIT_LEDGER.hash({ ...core, payload: AUDIT_LEDGER.canonical(fromJsonb) }), AUDIT_LEDGER.hash(core));
});

test("a store that isolates tenants refuses to read or verify without a tenant", async () => {
  const perTenant: LedgerStore<AuditPayload> = { kind: "postgres", append: async () => { throw new Error("unused"); }, readAll: async () => [], verify: async () => true, head: async () => ({ seq: 0, hash: GENESIS }) };
  const log = new AuditLog({ store: perTenant });
  assert.deepEqual(await log.query({ tenantId: "t1" }), []);
  await assert.rejects(() => log.query(), (e: unknown) => e instanceof AuditError && e.code === "TENANT_REQUIRED");
  await assert.rejects(() => log.verifyChain(), (e: unknown) => e instanceof AuditError && e.code === "TENANT_REQUIRED");
  assert.equal(await log.verifyChain("t1"), true);
  assert.equal((await log.exportEvidence("t1")).headHash, GENESIS);
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
  const events = await audit.query();
  assert.deepEqual(events.map((e) => e.outcome), ["denied", "success"]);
  assert.equal(events[1].correlationId, "corr-register-1");
  assert.equal(events[0].actor, "anonymous");
  assert.ok(!JSON.stringify(events).includes("CN=a"), "request bodies are not stored");
  assert.equal(await audit.verifyChain(), true);
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
  assert.equal((await app.inject({ method: "GET", url: "/v1/audit/events", headers: h })).json().chainValid, true, "in memory a platform admin still reads every tenant");
});
