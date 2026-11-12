import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConsentError, ConsentLedger } from "./services/consent-ledger.js";
import { buildServiceDisclosure, DisclosureError, NON_QUALIFIED_NOTICE } from "./services/legal-notices.js";
import { buildApp } from "./app.js";

const ev = { channel: "web", ip: "203.0.113.5" };
const base = { tenantId: "t1", subjectId: "s1", textVersion: "v1", text: "Acepto el tratamiento de mis datos.", evidence: ev };
const CFG = { providerName: "EasySign SRL", rnc: "101000019", address: "Santo Domingo, RD", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Según contrato", prices: "RD$ 500/mes", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su clave", claimsChannel: "soporte@easysign.test" };

test("marketing contact is denied by default and only allowed after an explicit grant", () => {
  const l = new ConsentLedger();
  assert.equal(l.hasConsent("t1", "s1", "marketing"), false);
  l.grant({ ...base, purpose: "personal_data_processing" });
  assert.equal(l.hasConsent("t1", "s1", "marketing"), false); // other purposes never imply marketing
  l.grant({ ...base, purpose: "marketing" });
  assert.equal(l.hasConsent("t1", "s1", "marketing"), true);
  l.withdraw("t1", "s1", "marketing", ev);
  assert.equal(l.hasConsent("t1", "s1", "marketing"), false);
  assert.equal(l.hasConsent("t2", "s1", "marketing"), false); // tenant isolation
  assert.throws(() => l.withdraw("t1", "s1", "marketing", ev), (e: unknown) => e instanceof ConsentError && e.code === "NOT_GRANTED");
  assert.equal(l.verifyChain(), true);
});

test("only the hash of the accepted text is stored, and tampering is detected on reload", () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-consent-")), "consents.jsonl");
  const l = new ConsentLedger({ filePath: file });
  const e = l.grant({ ...base, purpose: "signature_service_terms" });
  assert.equal(e.textHash.length, 64);
  assert.ok(!readFileSync(file, "utf8").includes("Acepto el tratamiento"));
  assert.equal(new ConsentLedger({ filePath: file }).hasConsent("t1", "s1", "signature_service_terms"), true);
  writeFileSync(file, readFileSync(file, "utf8").replace('"granted"', '"withdrawn"'));
  assert.throws(() => new ConsentLedger({ filePath: file }), (x: unknown) => x instanceof ConsentError && x.code === "CHAIN_BROKEN");
});

test("the service disclosure must be complete and may not use the reserved expression", () => {
  const d = buildServiceDisclosure(CFG, "2026-11-02");
  assert.equal(d.nonQualifiedNotice, NON_QUALIFIED_NOTICE);
  assert.equal(d.hash.length, 64);
  const { prices: _p, ...incomplete } = CFG;
  assert.throws(() => buildServiceDisclosure(incomplete, "v"), (e: unknown) => e instanceof DisclosureError && e.missing.includes("prices"));
  assert.throws(() => buildServiceDisclosure({ ...CFG, providerName: "Entidad de Certificación Demo" }, "v"), DisclosureError);
});

test("API: disclosure is public; consent writes need the admin token and fail closed", async () => {
  const open = buildApp({ registryAdminToken: undefined, disclosure: buildServiceDisclosure(CFG, "v1") });
  const pub = await open.inject({ method: "GET", url: "/v1/legal/disclosure" });
  assert.equal(pub.statusCode, 200);
  assert.match(pub.json().nonQualifiedNotice, /no tienen el valor jurídico/);
  assert.equal((await open.inject({ method: "POST", url: "/v1/consents", payload: { ...base, purpose: "marketing" } })).statusCode, 503);

  const app = buildApp({ registryAdminToken: "tok", disclosure: undefined });
  assert.equal((await app.inject({ method: "GET", url: "/v1/legal/disclosure" })).statusCode, 503);
  const h = { authorization: "Bearer tok" };
  assert.equal((await app.inject({ method: "POST", url: "/v1/consents", headers: { authorization: "Bearer x" }, payload: { ...base, purpose: "marketing" } })).statusCode, 401);
  assert.equal((await app.inject({ method: "POST", url: "/v1/consents", headers: h, payload: { ...base, purpose: "marketing" } })).statusCode, 201);
  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/t1/s1", headers: h })).json().marketingAllowed, true);
  assert.equal((await app.inject({ method: "POST", url: "/v1/consents/withdraw", headers: h, payload: { tenantId: "t1", subjectId: "s1", purpose: "marketing", evidence: ev } })).statusCode, 200);
  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/t1/s1", headers: h })).json().marketingAllowed, false);
});

test("system status carries the non-qualified notice", async () => {
  const s = (await buildApp({}).inject({ method: "GET", url: "/v1/system/status" })).json();
  assert.equal(s.legalNotice, NON_QUALIFIED_NOTICE);
});
