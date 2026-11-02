import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { buildSigningUrl, prepareDelivery, renderQrSvg, type DeliverableToken, type DeliveryProvider } from "./services/delivery.js";
import { SignatureWorkflow, WorkflowError } from "./services/signature-workflow.js";
import { buildServiceDisclosure } from "./services/legal-notices.js";
import { buildApp } from "./app.js";

const BASE = "https://firma.example.test";
const DOC = createHash("sha256").update("contrato").digest("hex");
const tok = (channel: DeliverableToken["channel"], over: Partial<DeliverableToken> = {}): DeliverableToken => ({ signerId: "s1", name: "Ana", email: "ana@x.test", phone: "+18095550100", order: 1, token: "T".repeat(43), channel, ...over });
const code = (c: string) => (e: unknown) => e instanceof WorkflowError && e.code === c;
const ev = { ip: "1.1.1.1" };
const DH = "d".repeat(64);
const DISCLOSURE = buildServiceDisclosure({ providerName: "EasySign SRL", rnc: "101000019", address: "Santo Domingo", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Contrato", prices: "RD$ 500", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su acceso", claimsChannel: "soporte@easysign.test" }, "v1");

test("the token travels in the URL fragment and the QR encodes that link", async () => {
  const url = buildSigningUrl(`${BASE}/`, "req-1", "s1", "TOKEN");
  assert.equal(url, `${BASE}/sign/req-1/s1#TOKEN`);
  assert.equal(new URL(url).search, "");
  assert.match(await renderQrSvg(url), /^<\?xml|^<svg/);
});

test("each channel behaves honestly: QR and link are manual, email/WhatsApp need a provider", async () => {
  const [qr, link, email, wa] = await prepareDelivery([tok("qr"), tok("link"), tok("email"), tok("whatsapp")], "req-1", "Contrato", BASE);
  assert.equal(qr.status, "manual"); assert.ok(qr.qrSvg?.includes("<svg")); assert.ok(qr.signingUrl?.includes("#"));
  assert.equal(link.status, "manual"); assert.equal(link.qrSvg, undefined);
  assert.equal(email.status, "pending_provider"); assert.ok(email.signingUrl); // nothing was sent: the admin gets the link
  assert.equal(wa.status, "pending_provider");

  const sent: Array<{ to: string; url: string }> = [];
  const providers: DeliveryProvider[] = [{ channel: "email", send: async (m) => { sent.push(m); } }, { channel: "whatsapp", send: async () => { throw new Error("down"); } }];
  const [e2, w2] = await prepareDelivery([tok("email"), tok("whatsapp")], "req-1", "Contrato", BASE, providers);
  assert.equal(e2.status, "sent"); assert.equal(e2.signingUrl, undefined); // the link is not echoed back when a provider delivered it
  assert.equal(sent[0].to, "ana@x.test");
  assert.equal(w2.status, "error"); assert.ok(w2.signingUrl); // provider failed: fall back to manual delivery

  const [noBase] = await prepareDelivery([tok("link")], "req-1", "Contrato", undefined);
  assert.equal(noBase.status, "error");
});

test("per-signer channel is validated, and reissue replaces the token, unlocks and can switch channel", () => {
  const w = new SignatureWorkflow();
  const base = { tenantId: "t1", documentName: "C", documentHash: DOC };
  assert.throws(() => w.create({ ...base, signers: [{ name: "A", email: "a@x.test", channel: "fax" as never }] }, "x"), code("INVALID_INPUT"));
  assert.throws(() => w.create({ ...base, signers: [{ name: "A", email: "a@x.test", channel: "whatsapp" }] }, "x"), code("INVALID_INPUT"));
  assert.throws(() => w.create({ ...base, signers: [{ name: "A", email: "a@x.test", channel: "whatsapp", phone: "8095550100" }] }, "x"), code("INVALID_INPUT"));

  const r = w.create({ ...base, signers: [{ name: "A", email: "a@x.test", channel: "email" }, { name: "B", email: "b@x.test", channel: "whatsapp", phone: "+18095550101" }] }, "x");
  assert.throws(() => w.reissue(r.id, r.signers[0].id), code("INVALID_STATE")); // not sent yet
  const [t1] = w.send(r.id).tokens;
  assert.equal(t1.channel, "email");
  for (let i = 0; i < 5; i++) assert.throws(() => w.view(r.id, t1.signerId, "bad-token-".repeat(5)), code("UNAUTHORIZED"));
  assert.throws(() => w.view(r.id, t1.signerId, t1.token), code("LOCKED"));

  const t2 = w.reissue(r.id, t1.signerId, "qr");
  assert.equal(t2.channel, "qr");
  assert.notEqual(t2.token, t1.token);
  assert.throws(() => w.view(r.id, t1.signerId, t1.token), code("UNAUTHORIZED")); // the old token is dead
  assert.doesNotThrow(() => w.view(r.id, t1.signerId, t2.token)); // and the lockout is cleared
  assert.throws(() => w.reissue(r.id, r.signers[1].id), code("INVALID_STATE")); // second signer is still waiting for their turn
  assert.throws(() => w.reissue(r.id, t1.signerId, "whatsapp"), code("INVALID_INPUT")); // no phone on file for the first signer
});

test("a reissued token survives a restart (only its hash is in the log)", async () => {
  const { mkdtempSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const file = join(mkdtempSync(join(tmpdir(), "easysign-rei-")), "wf.jsonl");
  const w = new SignatureWorkflow({ filePath: file });
  const r = w.create({ tenantId: "t1", documentName: "C", documentHash: DOC, signers: [{ name: "A", email: "a@x.test" }] }, "x");
  w.send(r.id);
  const t = w.reissue(r.id, r.signers[0].id, "qr");
  assert.ok(!readFileSync(file, "utf8").includes(t.token));
  assert.doesNotThrow(() => new SignatureWorkflow({ filePath: file }).view(r.id, t.signerId, t.token));
});

test("API: the client's channel choice, QR on screen, signing page, provider delivery and reissue", async () => {
  const sent: Array<{ to: string; url: string }> = [];
  const app = buildApp({ registryAdminToken: "tok", disclosure: DISCLOSURE, publicBaseUrl: BASE, deliveryProviders: [{ channel: "email", send: async (m) => { sent.push(m); } }], workflow: new SignatureWorkflow() });
  const h = { authorization: "Bearer tok" };
  const created = await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: h, payload: { tenantId: "t1", documentName: "Contrato", documentHash: DOC, signers: [{ name: "Ana", email: "ana@x.test", channel: "qr" }, { name: "Luis", email: "luis@x.test", channel: "email" }] } });
  assert.equal(created.statusCode, 201);
  const id = created.json().id;

  const sentRes = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: h, payload: { acknowledgeNoDocument: true } })).json();
  const d = sentRes.deliveries[0];
  assert.equal(d.channel, "qr");
  assert.ok(d.qrSvg.includes("<svg"));
  assert.match(d.signingUrl, new RegExp(`^${BASE}/sign/${id}/[0-9a-f-]{36}#`));
  const a = sentRes.tokens[0];

  // the page the QR opens is static, has no token, and is served with a strict CSP
  const page = await app.inject({ method: "GET", url: `/sign/${id}/${a.signerId}` });
  assert.equal(page.statusCode, 200);
  assert.match(String(page.headers["content-security-policy"]), /script-src 'self'/);
  assert.equal(page.headers["referrer-policy"], "no-referrer");
  assert.ok(!page.body.includes(a.token));
  const js = await app.inject({ method: "GET", url: "/sign/app.js" });
  assert.equal(js.statusCode, 200);
  assert.ok(!js.body.includes("innerHTML"), "the signing page never injects HTML");

  // Ana signs through the same API the page uses; Luis (email) is delivered by the provider, not echoed to anyone
  const base = `/v1/signature-workflows/${id}/signers/${a.signerId}`;
  await app.inject({ method: "POST", url: `${base}/view`, payload: { token: a.token } });
  await app.inject({ method: "POST", url: `${base}/consent`, payload: { token: a.token, disclosureHash: DISCLOSURE.hash } });
  const signed = await app.inject({ method: "POST", url: `${base}/sign`, payload: { token: a.token, documentHash: DOC } });
  assert.equal(signed.statusCode, 200);
  assert.ok(!JSON.stringify(signed.json()).includes("luis@x.test"));
  assert.equal(sent.length, 1);
  assert.equal(sent[0].to, "luis@x.test");
  assert.deepEqual((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/next-tokens`, headers: h })).json().deliveries, []);

  // Luis lost the email: the client switches him to an on-screen QR
  const luis = (await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}`, headers: h })).json().signers[1];
  const re = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/signers/${luis.id}/reissue`, headers: h, payload: { channel: "qr" } })).json();
  assert.equal(re.deliveries[0].channel, "qr");
  assert.ok(re.deliveries[0].qrSvg);
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/signers/${luis.id}/reissue`, payload: {} })).statusCode, 401);
});
