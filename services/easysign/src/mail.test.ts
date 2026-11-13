import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  CloudflareEmailProvider, MailError, NoopMailProvider, NoopMessagingProvider, emailDeliveryProviders, mailProviderFromEnv, maskEmail, otpEmail, signingLinkEmail,
} from "./services/mail.js";
import { prepareDelivery } from "./services/delivery.js";

// A fake Cloudflare API on this machine. Nothing in this file talks to the internet or uses a real token.
const TOKEN = "test-token-not-real";
const ACCOUNT = "acc123";
interface Seen { method: string; url: string; authorization: string; contentType: string; body: any }
type Reply = { status: number; body?: unknown; raw?: string; hang?: boolean };

async function fakeCloudflare(replies: Reply[]): Promise<{ baseUrl: string; seen: Seen[]; close: () => Promise<void> }> {
  const seen: Seen[] = [];
  const read = (req: IncomingMessage) => new Promise<string>((resolve) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => resolve(s)); });
  const server: Server = createServer(async (req, res) => {
    const raw = await read(req);
    seen.push({ method: String(req.method), url: String(req.url), authorization: String(req.headers.authorization ?? ""), contentType: String(req.headers["content-type"] ?? ""), body: raw ? JSON.parse(raw) : undefined });
    const reply = replies[Math.min(seen.length - 1, replies.length - 1)];
    if (reply.hang) return; // never answers: the client must give up by itself
    res.writeHead(reply.status, { "content-type": "application/json" });
    res.end(reply.raw ?? JSON.stringify(reply.body ?? {}));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return { baseUrl: `http://127.0.0.1:${port}/client/v4`, seen, close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }) };
}

const OK = (to: string): Reply => ({ status: 200, body: { success: true, errors: [], messages: [], result: { delivered: [to], permanent_bounces: [], queued: [], message_id: "m-1" } } });
const provider = (baseUrl: string, over: Partial<ConstructorParameters<typeof CloudflareEmailProvider>[0]> = {}) =>
  new CloudflareEmailProvider({ accountId: ACCOUNT, apiToken: TOKEN, from: { address: "noreply@firma.example.test", name: "EasySign" }, baseUrl, retryDelayMs: 1, ...over });
const MSG = { to: "ana@x.test", subject: "Documento pendiente de firma: Contrato", text: "hola", html: "<p>hola</p>" };
const mailError = (code: MailError["code"]) => (e: unknown) => e instanceof MailError && e.code === code && !e.message.includes(TOKEN);

test("Cloudflare: the request uses the documented endpoint, a Bearer token and from.address (not from.email)", async () => {
  const cf = await fakeCloudflare([OK("ana@x.test")]);
  try {
    const result = await provider(cf.baseUrl).send(MSG);
    assert.deepEqual(result, { status: "sent", messageId: "m-1" });
    assert.equal(cf.seen.length, 1);
    const r = cf.seen[0];
    assert.equal(r.method, "POST");
    assert.equal(r.url, `/client/v4/accounts/${ACCOUNT}/email/sending/send`);
    assert.equal(r.authorization, `Bearer ${TOKEN}`);
    assert.match(r.contentType, /^application\/json/);
    assert.deepEqual(r.body.from, { address: "noreply@firma.example.test", name: "EasySign" });
    assert.equal(r.body.from.email, undefined, "the REST API rejects from.email: the key is `address`");
    assert.equal(r.body.to, "ana@x.test");
    assert.equal(r.body.subject, MSG.subject);
    assert.equal(r.body.text, "hola");
    assert.equal(r.body.html, "<p>hola</p>");
    assert.ok(!JSON.stringify(r.body).includes(TOKEN), "the token travels only in the header");
  } finally { await cf.close(); }
});

test("Cloudflare: no sender name means from has only the address; reply_to is optional; the subject cannot carry line breaks", async () => {
  const cf = await fakeCloudflare([OK("ana@x.test")]);
  try {
    await provider(cf.baseUrl, { from: { address: "noreply@firma.example.test" }, replyTo: "soporte@firma.example.test" }).send({ ...MSG, subject: "Hola\r\nBcc: otro@x.test" });
    assert.deepEqual(cf.seen[0].body.from, { address: "noreply@firma.example.test" });
    assert.equal(cf.seen[0].body.reply_to, "soporte@firma.example.test");
    assert.equal(cf.seen[0].body.subject, "Hola Bcc: otro@x.test");
  } finally { await cf.close(); }
});

test("Cloudflare: a 4xx is a rejection, is not retried, and the error never contains the token", async () => {
  for (const status of [400, 401, 403, 422]) {
    const cf = await fakeCloudflare([{ status, body: { success: false, errors: [{ code: 10001, message: `sender not allowed ${TOKEN}` }] } }]);
    try {
      await assert.rejects(provider(cf.baseUrl).send(MSG), (e: unknown) => mailError("REJECTED")(e) && (e as MailError).status === status && /sender not allowed \[REDACTED\]/.test((e as MailError).message));
      assert.equal(cf.seen.length, 1, `a ${status} must not be retried`);
    } finally { await cf.close(); }
  }
});

test("Cloudflare: 5xx and 429 are retried a bounded number of times", async () => {
  const recovered = await fakeCloudflare([{ status: 503 }, { status: 429 }, OK("ana@x.test")]);
  try {
    assert.equal((await provider(recovered.baseUrl).send(MSG)).status, "sent");
    assert.equal(recovered.seen.length, 3);
  } finally { await recovered.close(); }

  const down = await fakeCloudflare([{ status: 500, raw: "<html>bad gateway</html>" }]);
  try {
    await assert.rejects(provider(down.baseUrl, { maxRetries: 2 }).send(MSG), (e: unknown) => mailError("UNAVAILABLE")(e) && (e as MailError).status === 500);
    assert.equal(down.seen.length, 3, "one attempt plus two retries, no more");
  } finally { await down.close(); }
});

test("Cloudflare: a 200 with success=false is a rejection, a permanent bounce is reported, queued is not an error", async () => {
  const refused = await fakeCloudflare([{ status: 200, body: { success: false, errors: [{ code: 1, message: "nope" }] } }]);
  try { await assert.rejects(provider(refused.baseUrl).send(MSG), mailError("REJECTED")); } finally { await refused.close(); }

  const bounced = await fakeCloudflare([{ status: 200, body: { success: true, result: { delivered: [], queued: [], permanent_bounces: ["ana@x.test"] } } }]);
  try { await assert.rejects(provider(bounced.baseUrl).send(MSG), mailError("BOUNCED")); } finally { await bounced.close(); }

  const queued = await fakeCloudflare([{ status: 200, body: { success: true, result: { delivered: [], queued: ["ana@x.test"], permanent_bounces: [] } } }]);
  try { assert.equal((await provider(queued.baseUrl).send(MSG)).status, "queued"); } finally { await queued.close(); }
});

test("Cloudflare: a server that never answers ends in a timeout, and an unreachable one in UNAVAILABLE", async () => {
  const silent = await fakeCloudflare([{ status: 200, hang: true }]);
  try {
    const started = Date.now();
    await assert.rejects(provider(silent.baseUrl, { timeoutMs: 150, maxRetries: 1 }).send(MSG), mailError("TIMEOUT"));
    assert.equal(silent.seen.length, 2);
    assert.ok(Date.now() - started < 3000, "the wait is bounded");
  } finally { await silent.close(); }

  const gone = await fakeCloudflare([OK("ana@x.test")]);
  await gone.close(); // nothing listens on that port any more
  await assert.rejects(provider(gone.baseUrl, { maxRetries: 0 }).send(MSG), mailError("UNAVAILABLE"));
});

test("Cloudflare: bad recipients and bad configuration are refused before any request", async () => {
  const cf = await fakeCloudflare([OK("ana@x.test")]);
  try {
    await assert.rejects(provider(cf.baseUrl).send({ ...MSG, to: "ana@x.test, otro@x.test" }), mailError("INVALID_MESSAGE"));
    await assert.rejects(provider(cf.baseUrl).send({ ...MSG, to: "sin-arroba" }), mailError("INVALID_MESSAGE"));
    assert.equal(cf.seen.length, 0);
  } finally { await cf.close(); }
  const base = { accountId: ACCOUNT, apiToken: TOKEN, from: { address: "noreply@firma.example.test" } };
  assert.throws(() => new CloudflareEmailProvider({ ...base, apiToken: "" }), mailError("CONFIG"));
  assert.throws(() => new CloudflareEmailProvider({ ...base, accountId: "../zones" }), mailError("CONFIG"));
  assert.throws(() => new CloudflareEmailProvider({ ...base, from: { address: "EasySign" } }), mailError("CONFIG"));
  assert.throws(() => new CloudflareEmailProvider({ ...base, baseUrl: "http://api.example.test/client/v4" }), mailError("CONFIG"), "the token must not travel over plain http");
  assert.doesNotThrow(() => new CloudflareEmailProvider(base)); // defaults to https://api.cloudflare.com/client/v4; nothing is sent here
});

test("provider selection by environment: none without credentials, explicit cloudflare needs token and account, anything else is refused", () => {
  assert.ok(mailProviderFromEnv({}) instanceof NoopMailProvider);
  assert.ok(mailProviderFromEnv({ EASYSIGN_MAIL_PROVIDER: "none" }) instanceof NoopMailProvider);
  const full = { EASYSIGN_MAIL_PROVIDER: "cloudflare", EASYSIGN_MAIL_FROM: "noreply@firma.example.test", EASYSIGN_MAIL_FROM_NAME: "EasySign", CLOUDFLARE_EMAIL_API_TOKEN: TOKEN, CLOUDFLARE_ACCOUNT_ID: ACCOUNT };
  const cf = mailProviderFromEnv(full);
  assert.ok(cf instanceof CloudflareEmailProvider);
  assert.equal(cf.enabled, true);
  assert.ok(!JSON.stringify(Object.keys(cf)).includes(TOKEN));
  for (const missing of ["CLOUDFLARE_EMAIL_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]) {
    assert.throws(() => mailProviderFromEnv({ ...full, [missing]: undefined }), mailError("CONFIG"), `${missing} is required`);
  }
  assert.throws(() => mailProviderFromEnv({ EASYSIGN_MAIL_PROVIDER: "sendgrid" }), mailError("CONFIG"));
});

test("no-op providers send nothing, so the link still goes back to the administrator", async () => {
  const noop = new NoopMailProvider();
  assert.equal(noop.enabled, false);
  assert.deepEqual(await noop.send(), { status: "not_sent" });
  assert.deepEqual(emailDeliveryProviders(noop, "EasySign"), []);
  const [d] = await prepareDelivery([{ signerId: "s1", name: "Ana", email: "ana@x.test", order: 1, token: "T".repeat(43), channel: "email" }], "req-1", "Contrato", "https://firma.example.test", emailDeliveryProviders(noop, "EasySign"));
  assert.equal(d.status, "pending_provider");
  assert.ok(d.signingUrl);

  const whatsapp = new NoopMessagingProvider();
  assert.equal(whatsapp.enabled, false);
  assert.deepEqual(await whatsapp.send(), { status: "not_sent" });
});

test("the signing link is emailed through the provider and is not echoed back", async () => {
  const cf = await fakeCloudflare([OK("ana@x.test")]);
  try {
    const url = "https://firma.example.test/sign/req-1/s1#" + "T".repeat(43);
    const [d] = await prepareDelivery([{ signerId: "s1", name: "Ana", email: "ana@x.test", order: 1, token: "T".repeat(43), channel: "email" }], "req-1", "Contrato de alquiler", "https://firma.example.test", emailDeliveryProviders(provider(cf.baseUrl), "EasySign"));
    assert.equal(d.status, "sent");
    assert.equal(d.signingUrl, undefined);
    const body = cf.seen[0].body;
    assert.equal(body.to, "ana@x.test");
    assert.equal(body.subject, "Documento pendiente de firma: Contrato de alquiler");
    assert.ok(body.text.includes(url) && body.html.includes(url));
  } finally { await cf.close(); }
});

test("templates: Spanish, plain, with the data escaped in HTML and the code out of the subject", () => {
  const link = signingLinkEmail({ to: "ana@x.test", name: "Ana <b>", documentName: 'Contrato "A&B"\r\nX', url: "https://firma.example.test/sign/r/s#tok", platformName: "EasySign" });
  assert.match(link.text, /Hola, Ana <b>:/);
  assert.match(link.text, /firma electrónica/);
  assert.ok(link.html.includes("Ana &lt;b&gt;") && !link.html.includes("<b>"));
  assert.ok(link.html.includes("Contrato &quot;A&amp;B&quot; X"));
  assert.ok(!/[\r\n]/.test(link.subject));
  assert.ok(!/<img|<table|unsubscribe|oferta|descuento/i.test(link.html), "transactional, not a newsletter");

  const otp = otpEmail({ to: "ana@x.test", name: "Ana", documentName: "Contrato", code: "042917", minutes: 10, platformName: "EasySign" });
  assert.ok(otp.text.includes("042917") && otp.html.includes("042917"));
  assert.ok(!otp.subject.includes("042917"));
  assert.match(otp.text, /Vence en 10 minutos/);

  assert.equal(maskEmail("ana.perez@example.do"), "a***@example.do");
  assert.equal(maskEmail("raro"), "***");
});

test("mailProviderFromEnv uses the shared Cloudflare Email Sending service automatically, like EasyCount", () => {
  const shared = { CLOUDFLARE_EMAIL_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: "a" };
  assert.ok(mailProviderFromEnv(shared) instanceof CloudflareEmailProvider, "token + account => Cloudflare without EASYSIGN_MAIL_PROVIDER");
  assert.ok(mailProviderFromEnv({ ...shared, EASYSIGN_MAIL_PROVIDER: "none" }) instanceof NoopMailProvider, "none still forces no sending");
  assert.ok(mailProviderFromEnv({ CLOUDFLARE_EMAIL_API_TOKEN: "t" }) instanceof NoopMailProvider, "half credentials without explicit provider => no sending");
});
