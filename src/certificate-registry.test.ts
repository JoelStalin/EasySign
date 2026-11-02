import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CertificateRegistry, RegistryError } from "./services/certificate-registry.js";
import { buildApp } from "./app.js";

const CERT = { serial: "4a7b9c1e", subject: "CN=Demo", issuer: "CN=Demo CA", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z", actor: "t" };
const code = (c: string) => (e: unknown) => e instanceof RegistryError && e.code === c;

test("lifecycle: issued -> suspended -> reactivated -> revoked, and revoked is final", () => {
  const r = new CertificateRegistry({ now: () => new Date("2026-06-01T00:00:00Z") });
  assert.equal(r.register(CERT).status, "active");
  assert.equal(r.get("4A7B9C1E").serial, "4A7B9C1E"); // serial is normalised to upper case
  assert.equal(r.suspend("4a7b9c1e", "t").status, "suspended");
  assert.equal(r.reactivate("4a7b9c1e", "t").status, "active");
  const revoked = r.revoke("4a7b9c1e", "t", "keyCompromise");
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.revocation?.withinSla, true);
  assert.throws(() => r.reactivate("4a7b9c1e", "t"), code("INVALID_TRANSITION"));
  assert.throws(() => r.revoke("4a7b9c1e", "t"), code("INVALID_TRANSITION"));
  assert.deepEqual(r.history("4a7b9c1e").map((e) => e.type), ["issued", "suspended", "reactivated", "revoked"]);
  assert.equal(r.verifyChain(), true);
});

test("invalid input and duplicates are rejected", () => {
  const r = new CertificateRegistry();
  r.register(CERT);
  assert.throws(() => r.register(CERT), code("ALREADY_EXISTS"));
  assert.throws(() => r.register({ ...CERT, serial: "ZZ" }), code("INVALID_INPUT"));
  assert.throws(() => r.register({ ...CERT, serial: "AA", notAfter: "2025-01-01T00:00:00Z" }), code("INVALID_INPUT"));
  assert.throws(() => r.get("FFFF"), code("NOT_FOUND"));
  assert.throws(() => r.reactivate("4a7b9c1e", "t"), code("INVALID_TRANSITION"));
});

test("an expired certificate stays queryable with its status (Annex I art. 36.3)", () => {
  let now = new Date("2026-06-01T00:00:00Z");
  const r = new CertificateRegistry({ now: () => now });
  r.register(CERT);
  r.revoke("4a7b9c1e", "t", "superseded");
  now = new Date("2030-01-01T00:00:00Z");
  const v = r.get("4a7b9c1e");
  assert.equal(v.expired, true);
  assert.equal(v.status, "revoked");
});

test("a revocation published more than 24 h after the request is flagged", () => {
  const r = new CertificateRegistry({ now: () => new Date("2026-06-03T00:00:00Z") });
  r.register(CERT);
  const v = r.revoke("4a7b9c1e", "t", "keyCompromise", "2026-06-01T00:00:00Z");
  assert.equal(v.revocation?.withinSla, false);
  assert.equal(r.slaBreaches().length, 1);
  assert.throws(() => new CertificateRegistry({ now: () => new Date("2026-06-01T00:00:00Z") }).revoke("x", "t", "unspecified", "2030-01-01T00:00:00Z"));
});

test("the log is durable, reloads and detects tampering", () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-reg-")), "registry.jsonl");
  const a = new CertificateRegistry({ filePath: file });
  a.register(CERT);
  a.revoke("4a7b9c1e", "t", "keyCompromise");
  const b = new CertificateRegistry({ filePath: file });
  assert.equal(b.get("4a7b9c1e").status, "revoked");
  assert.equal(b.verifyChain(), true);

  writeFileSync(file, readFileSync(file, "utf8").replace("keyCompromise", "unspecified"));
  assert.throws(() => new CertificateRegistry({ filePath: file }), code("CHAIN_BROKEN"));
});

test("API: public reads work without credentials; writes need the admin token and fail closed without one", async () => {
  const noToken = buildApp({ registryAdminToken: undefined });
  assert.equal((await noToken.inject({ method: "POST", url: "/v1/registry/certificates", payload: CERT })).statusCode, 503);

  const app = buildApp({ registryAdminToken: "s3cret-token" });
  const bad = await app.inject({ method: "POST", url: "/v1/registry/certificates", headers: { authorization: "Bearer nope" }, payload: CERT });
  assert.equal(bad.statusCode, 401);
  const auth = { authorization: "Bearer s3cret-token" };
  const { actor: _actor, ...payload } = CERT;
  assert.equal((await app.inject({ method: "POST", url: "/v1/registry/certificates", headers: auth, payload })).statusCode, 201);

  const pub = await app.inject({ method: "GET", url: "/v1/registry/certificates/4a7b9c1e" });
  assert.equal(pub.statusCode, 200);
  assert.equal(pub.json().status, "active");
  assert.equal("actor" in pub.json(), false);

  assert.equal((await app.inject({ method: "POST", url: "/v1/registry/certificates/4a7b9c1e/revoke", headers: auth, payload: { reason: "keyCompromise" } })).statusCode, 200);
  assert.equal((await app.inject({ method: "POST", url: "/v1/registry/certificates/4a7b9c1e/reactivate", headers: auth })).statusCode, 409);
  const crl = (await app.inject({ method: "GET", url: "/v1/registry/revocations" })).json();
  assert.equal(crl.revoked[0].serial, "4A7B9C1E");
  assert.equal((await app.inject({ method: "GET", url: "/v1/registry/certificates/FFFF" })).statusCode, 404);
  assert.equal((await app.inject({ method: "GET", url: "/v1/registry/certificates?status=revoked" })).json().total, 1);
});

test("system status no longer claims DGII compliance readiness", async () => {
  const s = (await buildApp({}).inject({ method: "GET", url: "/v1/system/status" })).json();
  assert.equal(s.dgiiComplianceReady, false);
  assert.equal(s.accredited, false);
});
