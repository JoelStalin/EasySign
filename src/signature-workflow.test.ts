import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignatureWorkflow, WorkflowError } from "./services/signature-workflow.js";
import { buildServiceDisclosure } from "./services/legal-notices.js";
import { ConsentLedger } from "./services/consent-ledger.js";
import { AuditLog } from "./services/audit-log.js";
import { buildApp } from "./app.js";

const DOC = createHash("sha256").update("contrato de arrendamiento").digest("hex");
const input = (over: Record<string, unknown> = {}) => ({ tenantId: "t1", documentName: "Contrato", documentHash: DOC, signers: [{ name: "Ana", email: "ana@x.test" }, { name: "Luis", email: "luis@x.test" }], ...over });
const code = (c: string) => (e: unknown) => e instanceof WorkflowError && e.code === c;
const ev = { ip: "203.0.113.9", userAgent: "test" };
const DH = "d".repeat(64);

function fullSign(w: SignatureWorkflow, id: string, t: { signerId: string; token: string }) {
  w.view(id, t.signerId, t.token);
  w.consent(id, t.signerId, t.token, DH, DH, ev);
  return w.sign(id, t.signerId, t.token, DOC, ev);
}

test("sequential flow: only the first signer gets a token; the next one is issued after each signature; request completes", () => {
  const w = new SignatureWorkflow();
  const r = w.create(input(), "admin");
  assert.equal(r.status, "draft");
  const { tokens } = w.send(r.id);
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].order, 1);

  const second = r.signers[1];
  assert.throws(() => w.view(r.id, second.id, "x".repeat(43)), code("UNAUTHORIZED"));

  const out = fullSign(w, r.id, tokens[0]);
  assert.equal(out.next.length, 1);
  assert.equal(out.next[0].signerId, second.id);
  assert.equal(out.request.status, "pending");

  const done = fullSign(w, r.id, out.next[0]);
  assert.equal(done.request.status, "completed");
  assert.ok(done.request.completedAt);
  const evidence = w.evidence(r.id);
  assert.equal(evidence.chainValid, true);
  assert.match(evidence.notice, /no tienen el valor jurídico/);
  assert.deepEqual(evidence.events.map((e) => e.type), ["created", "sent", "viewed", "consented", "signed", "viewed", "consented", "signed", "completed"]);
  assert.equal(evidence.packageHash.length, 64);
});

test("parallel flow notifies everyone at once", () => {
  const w = new SignatureWorkflow();
  const r = w.create(input({ ordering: "parallel" }), "admin");
  assert.equal(w.send(r.id).tokens.length, 2);
});

test("signing needs consent, the right document hash, and a valid token; five failures lock the signer", () => {
  const w = new SignatureWorkflow();
  const r = w.create(input(), "admin");
  const [t] = w.send(r.id).tokens;
  assert.throws(() => w.consent(r.id, t.signerId, t.token, DH, DH, ev), code("INVALID_STATE")); // must view first
  w.view(r.id, t.signerId, t.token);
  assert.throws(() => w.sign(r.id, t.signerId, t.token, DOC, ev), code("INVALID_STATE")); // no consent yet
  assert.throws(() => w.consent(r.id, t.signerId, t.token, "e".repeat(64), DH, ev), code("INVALID_INPUT")); // stale disclosure
  w.consent(r.id, t.signerId, t.token, DH, DH, ev);
  assert.throws(() => w.sign(r.id, t.signerId, t.token, "f".repeat(64), ev), code("DOCUMENT_MISMATCH"));
  for (let i = 0; i < 5; i++) assert.throws(() => w.sign(r.id, t.signerId, "wrong-token-".repeat(4), DOC, ev), code("UNAUTHORIZED"));
  assert.throws(() => w.sign(r.id, t.signerId, t.token, DOC, ev), code("LOCKED")); // even the right token is refused now
});

test("a request expires, and a declined request is cancelled", () => {
  let now = new Date("2026-06-01T00:00:00Z");
  const w = new SignatureWorkflow({ now: () => now });
  const r = w.create(input({ expiresInHours: 1 }), "admin");
  const [t] = w.send(r.id).tokens;
  now = new Date("2026-06-01T02:00:00Z");
  assert.throws(() => w.view(r.id, t.signerId, t.token), code("EXPIRED"));
  assert.equal(w.get(r.id).status, "expired");

  const d = new SignatureWorkflow();
  const r2 = d.create(input(), "admin");
  const [t2] = d.send(r2.id).tokens;
  const after = d.decline(r2.id, t2.signerId, t2.token, "no estoy de acuerdo");
  assert.equal(after.status, "cancelled");
  assert.throws(() => d.cancel(r2.id, "x"), code("INVALID_STATE"));
});

test("input validation", () => {
  const w = new SignatureWorkflow();
  assert.throws(() => w.create(input({ documentHash: "nope" }), "a"), code("INVALID_INPUT"));
  assert.throws(() => w.create(input({ signers: [] }), "a"), code("INVALID_INPUT"));
  assert.throws(() => w.create(input({ signers: [{ name: "A", email: "a@x.test" }, { name: "B", email: "A@x.test" }] }), "a"), code("INVALID_INPUT"));
  assert.throws(() => w.create(input({ signers: [{ name: "A", email: "bad" }] }), "a"), code("INVALID_INPUT"));
  assert.throws(() => w.create(input({ expiresInHours: 0 }), "a"), code("INVALID_INPUT"));
  assert.throws(() => w.get("missing"), code("NOT_FOUND"));
});

test("durable log reloads state, never stores tokens, and detects tampering", () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-wf-")), "wf.jsonl");
  const w = new SignatureWorkflow({ filePath: file });
  const r = w.create(input(), "admin");
  const [t] = w.send(r.id).tokens;
  const raw = readFileSync(file, "utf8");
  assert.ok(!raw.includes(t.token), "the clear token is never written");
  const back = new SignatureWorkflow({ filePath: file });
  assert.equal(back.get(r.id).status, "pending");
  assert.doesNotThrow(() => back.view(r.id, t.signerId, t.token)); // the stored hash still validates the token
  writeFileSync(file, raw.replace("Contrato", "Otro contrato"));
  assert.throws(() => new SignatureWorkflow({ filePath: file }), code("CHAIN_BROKEN"));
});

test("API: end to end with consent ledger, signer privacy, audit without tokens, and fail-closed admin", async () => {
  const disclosure = buildServiceDisclosure({ providerName: "EasySign SRL", rnc: "101000019", address: "Santo Domingo", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Contrato", prices: "RD$ 500", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su acceso", claimsChannel: "soporte@easysign.test" }, "v1");
  const consents = new ConsentLedger();
  const audit = new AuditLog();
  const app = buildApp({ registryAdminToken: "tok", disclosure, consentLedger: consents, auditLog: audit, workflow: new SignatureWorkflow() });
  const h = { authorization: "Bearer tok" };

  assert.equal((await buildApp({ registryAdminToken: undefined }).inject({ method: "POST", url: "/v1/signature-workflows", payload: input() })).statusCode, 503);
  assert.equal((await app.inject({ method: "POST", url: "/v1/signature-workflows", payload: input() })).statusCode, 401);

  const created = await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: h, payload: input() });
  assert.equal(created.statusCode, 201);
  const id = created.json().id;
  const sent = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: h })).json();
  const a = sent.tokens[0];
  const base = `/v1/signature-workflows/${id}/signers/${a.signerId}`;

  const view = await app.inject({ method: "POST", url: `${base}/view`, payload: { token: a.token } });
  assert.equal(view.statusCode, 200);
  assert.ok(!JSON.stringify(view.json()).includes("luis@x.test"), "a signer cannot see the other signers' emails");
  assert.equal(view.json().disclosure.version, "v1");
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/does-not-exist/signers/x/view`, payload: { token: "t".repeat(43) } })).statusCode, 401); // existence is not revealed

  assert.equal((await app.inject({ method: "POST", url: `${base}/sign`, payload: { token: a.token, documentHash: DOC } })).statusCode, 409); // no consent yet
  assert.equal((await app.inject({ method: "POST", url: `${base}/consent`, payload: { token: a.token, disclosureHash: disclosure.hash } })).statusCode, 200);
  assert.equal(consents.hasConsent("t1", a.signerId, "signature_service_terms"), true);
  assert.equal((await app.inject({ method: "POST", url: `${base}/sign`, payload: { token: a.token, documentHash: DOC } })).statusCode, 200);

  const next = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/next-tokens`, headers: h })).json().tokens;
  assert.equal(next.length, 1);
  const b = next[0];
  const baseB = `/v1/signature-workflows/${id}/signers/${b.signerId}`;
  await app.inject({ method: "POST", url: `${baseB}/view`, payload: { token: b.token } });
  await app.inject({ method: "POST", url: `${baseB}/consent`, payload: { token: b.token, disclosureHash: disclosure.hash } });
  const last = await app.inject({ method: "POST", url: `${baseB}/sign`, payload: { token: b.token, documentHash: DOC } });
  assert.equal(last.json().status, "completed");

  const evidence = (await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}/evidence`, headers: h })).json();
  assert.equal(evidence.request.status, "completed");
  assert.equal(evidence.chainValid, true);

  const logged = JSON.stringify(audit.query());
  assert.ok(!logged.includes(a.token) && !logged.includes(b.token), "tokens never reach the audit ledger");
  assert.ok(audit.query().some((e) => e.actor === "signer" && e.outcome === "success"));
  assert.equal(audit.verifyChain(), true);
});

test("API: requests cannot be sent until the service disclosure is published", async () => {
  const app = buildApp({ registryAdminToken: "tok", disclosure: undefined, workflow: new SignatureWorkflow() });
  const h = { authorization: "Bearer tok" };
  const id = (await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: h, payload: input() })).json().id;
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: h })).statusCode, 503);
});
