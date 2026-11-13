import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { Script } from "node:vm";
import { OtpError, SignerOtpService } from "./services/signer-otp.js";
import { SignatureWorkflow, WorkflowError } from "./services/signature-workflow.js";
import { AuditLog } from "./services/audit-log.js";
import { buildServiceDisclosure } from "./services/legal-notices.js";
import type { MailMessage, MailProvider } from "./services/mail.js";
import { buildApp } from "./app.js";

const DOC = createHash("sha256").update("contrato").digest("hex");
const DISCLOSURE = buildServiceDisclosure({ providerName: "EasySign SRL", rnc: "101000019", address: "Santo Domingo", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Contrato", prices: "RD$ 500", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su acceso", claimsChannel: "soporte@easysign.test" }, "v1");
const otpError = (code: OtpError["code"]) => (e: unknown) => e instanceof OtpError && e.code === code;
const MIN = 60_000;

/** A clock the test moves by hand. */
const clock = (start = Date.parse("2026-11-12T12:00:00Z")) => { let t = start; return { now: () => new Date(t), advance: (ms: number) => { t += ms; } }; };
const other = (code: string) => (code === "000000" ? "000001" : "000000");

// ---------------------------------------------------------------- service

test("OTP: a correct 6-digit code verifies once and cannot be reused", () => {
  const otp = new SignerOtpService();
  const { code, expiresAt } = otp.issue("r:s");
  assert.match(code, /^\d{6}$/);
  assert.ok(expiresAt.getTime() - Date.now() <= 10 * MIN && expiresAt.getTime() - Date.now() > 9 * MIN);
  assert.doesNotThrow(() => otp.verify("r:s", code));
  assert.throws(() => otp.verify("r:s", code), otpError("NO_CODE"), "single use");
  assert.throws(() => otp.verify("another:signer", code), otpError("NO_CODE"), "a code belongs to one signer of one request");
});

test("OTP: only a salted hash is kept, never the code", () => {
  const a = new SignerOtpService({ generate: () => "042917" });
  a.issue("r:s1"); a.issue("r:s2");
  const dump = inspect(a, { depth: 8 });
  assert.ok(!dump.includes("042917"));
  const entries = (a as unknown as { entries: Map<string, { code: { salt: Buffer; hash: Buffer } }> }).entries;
  const h1 = entries.get("r:s1")!.code, h2 = entries.get("r:s2")!.code;
  assert.equal(h1.hash.length, 32);
  assert.notEqual(h1.hash.toString("hex"), h2.hash.toString("hex"), "same code, different salt, different hash");
  assert.notEqual(h1.hash.toString("hex"), createHash("sha256").update("042917").digest("hex"), "not a bare hash of the code");
});

test("OTP: a wrong code is refused and five wrong tries kill the code, even for the right one", () => {
  const otp = new SignerOtpService();
  const { code } = otp.issue("r:s");
  for (let left = 4; left >= 0; left--) {
    assert.throws(() => otp.verify("r:s", other(code)), (e: unknown) => otpError("INVALID")(e) && (e as OtpError).meta.attemptsLeft === left);
  }
  assert.throws(() => otp.verify("r:s", code), otpError("TOO_MANY_ATTEMPTS"));
  assert.throws(() => otp.verify("r:s", code), otpError("TOO_MANY_ATTEMPTS"));
  for (const junk of ["", "12345", "1234567", "abcdef", "042917 "]) assert.throws(() => new SignerOtpService({ generate: () => "042917" }).verify("x", junk), otpError("NO_CODE"));
});

test("OTP: the code expires after 10 minutes", () => {
  const c = clock();
  const otp = new SignerOtpService({ now: c.now });
  const first = otp.issue("r:s");
  c.advance(10 * MIN - 1);
  assert.doesNotThrow(() => otp.verify("r:s", first.code), "still valid one millisecond before");
  c.advance(2 * MIN);
  const second = otp.issue("r:s");
  c.advance(10 * MIN);
  assert.throws(() => otp.verify("r:s", second.code), otpError("EXPIRED"));
  assert.throws(() => otp.verify("r:s", second.code), otpError("NO_CODE"));
});

test("OTP: resend is limited (one per minute, five per hour) and a new code replaces the old one", () => {
  const c = clock();
  const codes = ["111111", "222222", "333333", "444444", "555555", "666666", "777777"];
  const otp = new SignerOtpService({ now: c.now, generate: () => codes.shift() as string });
  otp.issue("r:s"); // 111111
  assert.throws(() => otp.issue("r:s"), (e: unknown) => otpError("RESEND_TOO_SOON")(e) && (e as OtpError).meta.retryAfterSeconds === 60);
  c.advance(59_000);
  assert.throws(() => otp.issue("r:s"), (e: unknown) => otpError("RESEND_TOO_SOON")(e) && (e as OtpError).meta.retryAfterSeconds === 1);
  c.advance(1_000);
  otp.issue("r:s"); // 222222
  assert.throws(() => otp.verify("r:s", "111111"), otpError("INVALID"), "the previous code is dead");
  assert.doesNotThrow(() => otp.verify("r:s", "222222"));
  for (let i = 0; i < 3; i++) { c.advance(MIN); otp.issue("r:s"); } // five sends in the hour
  c.advance(MIN);
  assert.throws(() => otp.issue("r:s"), otpError("RESEND_LIMIT"));
  assert.doesNotThrow(() => otp.issue("other:signer"), "the limit is per signer");
  c.advance(60 * MIN);
  assert.doesNotThrow(() => otp.issue("r:s"));
  otp.revoke("r:s");
  assert.throws(() => otp.verify("r:s", "666666"), otpError("NO_CODE"), "a revoked code is not valid");
});

// ---------------------------------------------------------------- workflow

test("workflow: with requireOtp nobody signs before the code is verified, and the events carry no code", () => {
  const file = join(mkdtempSync(join(tmpdir(), "easysign-otp-")), "wf.jsonl");
  const w = new SignatureWorkflow({ filePath: file });
  const is = (c: string) => (e: unknown) => e instanceof WorkflowError && e.code === c;
  const r = w.create({ tenantId: "t1", documentName: "C", documentHash: DOC, requireOtp: true, signers: [{ name: "Ana", email: "ana@x.test" }] }, "x");
  assert.equal(r.requireOtp, true);
  const [t] = w.send(r.id).tokens;
  w.view(r.id, t.signerId, t.token);
  w.consent(r.id, t.signerId, t.token, DISCLOSURE.hash, DISCLOSURE.hash, {});
  assert.throws(() => w.sign(r.id, t.signerId, t.token, DOC, {}), is("OTP_REQUIRED"));
  assert.throws(() => w.otpContext(r.id, t.signerId, "wrong-token-".repeat(4)), is("UNAUTHORIZED"));
  assert.deepEqual(w.otpContext(r.id, t.signerId, t.token), { tenantId: "t1", documentName: "C", name: "Ana", email: "ana@x.test" });
  w.otpEvent(r.id, t.signerId, t.token, "otp_requested", { channel: "email", expiresAt: "2026-11-12T12:10:00.000Z" });
  w.otpEvent(r.id, t.signerId, t.token, "otp_failed", { channel: "email", reason: "INVALID" });
  assert.throws(() => w.sign(r.id, t.signerId, t.token, DOC, {}), is("OTP_REQUIRED"), "asking for a code or failing it does not unlock signing");
  w.otpEvent(r.id, t.signerId, t.token, "otp_verified", { channel: "email" });
  assert.throws(() => w.otpContext(r.id, t.signerId, t.token), is("INVALID_STATE"), "already verified");

  // the verification survives a restart (it is an event of the chained log) and the chain stays valid
  const again = new SignatureWorkflow({ filePath: file });
  assert.ok(again.get(r.id).signers[0].otpVerifiedAt);
  assert.equal(again.get(r.id).requireOtp, true);
  assert.equal(again.sign(r.id, t.signerId, t.token, DOC, {}).request.status, "completed");
  const ev = again.evidence(r.id);
  assert.equal(ev.chainValid, true);
  assert.deepEqual(ev.events.map((e) => e.type).filter((x) => x.startsWith("otp_")), ["otp_requested", "otp_failed", "otp_verified"]);

  // a request without requireOtp is untouched
  const plain = w.create({ tenantId: "t1", documentName: "C", documentHash: DOC, signers: [{ name: "Ana", email: "ana@x.test" }] }, "x");
  assert.equal(plain.requireOtp, undefined);
  const [p] = w.send(plain.id).tokens;
  w.view(plain.id, p.signerId, p.token);
  assert.throws(() => w.otpContext(plain.id, p.signerId, p.token), is("INVALID_STATE"));
});

// ---------------------------------------------------------------- API

class CapturingMail implements MailProvider {
  public readonly name = "test";
  public readonly enabled = true;
  public readonly sent: MailMessage[] = [];
  public failNext = false;
  public async send(message: MailMessage) {
    if (this.failNext) { this.failNext = false; throw new Error("provider down"); }
    this.sent.push(message);
    return { status: "sent" as const };
  }
  public lastCode(): string { return (/^\d{6}$/m.exec(this.sent[this.sent.length - 1].text) as RegExpExecArray)[0]; }
}

const H = { authorization: "Bearer tok" };
async function setup(requireOtp = true) {
  const c = clock();
  const mail = new CapturingMail();
  const file = join(mkdtempSync(join(tmpdir(), "easysign-otp-api-")), "wf.jsonl");
  const auditLog = new AuditLog();
  const app = buildApp({ registryAdminToken: "tok", disclosure: DISCLOSURE, publicBaseUrl: "https://firma.example.test", workflow: new SignatureWorkflow({ filePath: file }), auditLog, mailProvider: mail, otp: new SignerOtpService({ now: c.now }) });
  const created = await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: H, payload: { tenantId: "t1", documentName: "Contrato", documentHash: DOC, ...(requireOtp ? { requireOtp: true } : {}), signers: [{ name: "Ana", email: "ana@x.test", channel: "link" }] } });
  assert.equal(created.statusCode, 201);
  const id = created.json().id as string;
  const sent = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: H, payload: { acknowledgeNoDocument: true } })).json();
  const { signerId, token } = sent.tokens[0] as { signerId: string; token: string };
  const base = `/v1/signature-workflows/${id}/signers/${signerId}`;
  const post = (action: string, extra: Record<string, unknown> = {}, tk = token) => app.inject({ method: "POST", url: `${base}/${action}`, payload: { token: tk, ...extra } });
  return { app, c, mail, file, auditLog, id, signerId, token, post };
}

test("API: requireOtp is refused when no mail provider is configured", async () => {
  const app = buildApp({ registryAdminToken: "tok", disclosure: DISCLOSURE, publicBaseUrl: "https://firma.example.test", workflow: new SignatureWorkflow() });
  const payload = { tenantId: "t1", documentName: "Contrato", documentHash: DOC, signers: [{ name: "Ana", email: "ana@x.test" }] };
  const refused = await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: H, payload: { ...payload, requireOtp: true } });
  assert.equal(refused.statusCode, 503);
  assert.equal(refused.json().error, "OTP_CHANNEL_NOT_CONFIGURED");
  assert.equal((await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: H, payload })).statusCode, 201, "without requireOtp nothing changes");
  assert.equal((await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: H, payload: { ...payload, requireOtp: "yes" } })).statusCode, 400);
});

test("API: full flow with requireOtp, and neither the responses nor the ledgers contain the code", async () => {
  const s = await setup();
  const view = (await s.post("view")).json();
  assert.equal(view.requireOtp, true);
  assert.equal(view.otpVerified, false);
  assert.equal(view.otpEmailHint, "a***@x.test");
  assert.ok(!JSON.stringify(view).includes("ana@x.test"));
  await s.post("consent", { disclosureHash: DISCLOSURE.hash });

  const blocked = await s.post("sign", { documentHash: DOC });
  assert.equal(blocked.statusCode, 403);
  assert.equal(blocked.json().error, "OTP_REQUIRED");

  assert.equal((await s.post("otp/request", {}, "not-the-signers-token-".repeat(2))).statusCode, 401, "the code is only sent to whoever holds the link");
  assert.equal(s.mail.sent.length, 0);

  const asked = await s.post("otp/request");
  assert.equal(asked.statusCode, 200);
  assert.deepEqual(Object.keys(asked.json()).sort(), ["channel", "expiresAt", "sent", "sentTo"]);
  assert.equal(asked.json().sentTo, "a***@x.test");
  assert.equal(s.mail.sent.length, 1);
  assert.equal(s.mail.sent[0].to, "ana@x.test", "the code goes to the signer's email, whatever channel carried the link");
  const code = s.mail.lastCode();
  assert.ok(!asked.body.includes(code), "the code travels only by email");

  const tooSoon = await s.post("otp/request");
  assert.equal(tooSoon.statusCode, 429);
  assert.equal(tooSoon.json().error, "OTP_RESEND_TOO_SOON");
  assert.equal(tooSoon.headers["retry-after"], "60");
  assert.equal(s.mail.sent.length, 1);

  assert.equal((await s.post("otp/verify", { code: "12345" })).statusCode, 400, "malformed code");
  const wrong = await s.post("otp/verify", { code: other(code) });
  assert.equal(wrong.statusCode, 400);
  assert.equal(wrong.json().error, "OTP_INVALID");
  assert.equal(wrong.json().attemptsLeft, 4);
  assert.equal((await s.post("sign", { documentHash: DOC })).statusCode, 403);

  const verified = await s.post("otp/verify", { code });
  assert.equal(verified.statusCode, 200);
  assert.equal(verified.json().otpVerified, true);
  const reuse = await s.post("otp/verify", { code });
  assert.equal(reuse.statusCode, 409, "the code cannot be used twice");
  assert.equal((await s.post("otp/request")).statusCode, 409, "nothing more to verify");

  const signed = await s.post("sign", { documentHash: DOC });
  assert.equal(signed.statusCode, 200);
  assert.equal(signed.json().status, "completed");

  // evidence: the steps are in the chained workflow log and in the audit ledger, without the code
  const evidence = (await s.app.inject({ method: "GET", url: `/v1/signature-workflows/${s.id}/evidence`, headers: H })).json();
  assert.deepEqual(evidence.events.map((e: { type: string }) => e.type), ["created", "sent", "viewed", "consented", "otp_requested", "otp_failed", "otp_verified", "signed", "completed"]);
  assert.equal(evidence.chainValid, true);
  assert.ok(evidence.request.signers[0].otpVerifiedAt);
  const audit = s.auditLog.query({ correlationId: s.id });
  assert.deepEqual(audit.map((e) => `${e.action}:${e.outcome}`), ["signer:otp_requested:success", "signer:otp_requested:denied", "signer:otp_failed:denied", "signer:otp_verified:success"]);
  assert.equal(audit[0].actor, `signer:${s.signerId}`);
  assert.equal(audit[0].tenantId, "t1");
  for (const text of [readFileSync(s.file, "utf8"), JSON.stringify(audit), JSON.stringify(evidence)]) {
    assert.ok(!text.includes(code), "no ledger or evidence package contains the code");
    assert.ok(!text.includes(s.token));
  }
});

test("API: an expired code is refused and a new one can be requested", async () => {
  const s = await setup();
  await s.post("view"); await s.post("consent", { disclosureHash: DISCLOSURE.hash });
  await s.post("otp/request");
  const old = s.mail.lastCode();
  s.c.advance(10 * MIN);
  const expired = await s.post("otp/verify", { code: old });
  assert.equal(expired.statusCode, 410);
  assert.equal(expired.json().error, "OTP_EXPIRED");
  assert.equal((await s.post("sign", { documentHash: DOC })).statusCode, 403);
  assert.equal((await s.post("otp/request")).statusCode, 200);
  assert.equal((await s.post("otp/verify", { code: s.mail.lastCode() })).statusCode, 200);
  assert.equal((await s.post("sign", { documentHash: DOC })).statusCode, 200);
});

test("API: after five wrong codes even the right one is refused, and signing stays blocked", async () => {
  const s = await setup();
  await s.post("view"); await s.post("consent", { disclosureHash: DISCLOSURE.hash });
  await s.post("otp/request");
  const code = s.mail.lastCode();
  for (let i = 0; i < 5; i++) assert.equal((await s.post("otp/verify", { code: other(code) })).json().error, "OTP_INVALID");
  const locked = await s.post("otp/verify", { code });
  assert.equal(locked.statusCode, 429);
  assert.equal(locked.json().error, "OTP_TOO_MANY_ATTEMPTS");
  assert.equal((await s.post("sign", { documentHash: DOC })).statusCode, 403);
  // the ledger is not flooded: only the five bounded failures were written
  assert.equal(s.auditLog.query({ correlationId: s.id, action: "signer:otp_failed" }).length, 5);
});

test("API: if the email cannot be sent the code is revoked and the signer is told to retry", async () => {
  const s = await setup();
  await s.post("view"); await s.post("consent", { disclosureHash: DISCLOSURE.hash });
  s.mail.failNext = true;
  const failed = await s.post("otp/request");
  assert.equal(failed.statusCode, 502);
  assert.equal(failed.json().error, "OTP_DELIVERY_FAILED");
  assert.ok(!failed.body.includes("provider down"), "provider errors are not shown to the signer");
  assert.equal((await s.post("otp/verify", { code: "000000" })).json().error, "OTP_NO_CODE");
  assert.deepEqual(s.auditLog.query({ correlationId: s.id }).map((e) => e.outcome), ["error"]);
});

test("API: a request without requireOtp has no OTP step and signs as before", async () => {
  const s = await setup(false);
  const view = (await s.post("view")).json();
  assert.equal(view.requireOtp, false);
  assert.equal(view.otpEmailHint, undefined);
  await s.post("consent", { disclosureHash: DISCLOSURE.hash });
  assert.equal((await s.post("otp/request")).statusCode, 409);
  assert.equal(s.mail.sent.length, 0);
  assert.equal((await s.post("sign", { documentHash: DOC })).statusCode, 200);
});

test("signing page: the script still parses, has the OTP step and never injects HTML", async () => {
  const app = buildApp({ registryAdminToken: "tok", disclosure: DISCLOSURE, workflow: new SignatureWorkflow() });
  const js = (await app.inject({ method: "GET", url: "/sign/app.js" })).body;
  assert.doesNotThrow(() => new Script(js));
  assert.ok(js.includes("otp/request") && js.includes("otp/verify"));
  assert.ok(!js.includes("innerHTML"));
});
