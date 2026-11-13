import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DocumentError, DocumentStore, MAX_DOCUMENT_BYTES, detectType, safeFileName, sha256Hex } from "./services/document-store.js";
import { SignatureWorkflow, WorkflowError } from "./services/signature-workflow.js";
import { AuditLog } from "./services/audit-log.js";
import { buildServiceDisclosure } from "./services/legal-notices.js";
import { buildApp } from "./app.js";

const PDF = Buffer.from("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n");
const PDF_HASH = sha256Hex(PDF);
const code = (c: string) => (e: unknown) => (e instanceof DocumentError || e instanceof WorkflowError) && e.code === c;
const DISCLOSURE = buildServiceDisclosure({ providerName: "EasySign SRL", rnc: "101000019", address: "Santo Domingo", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Contrato", prices: "RD$ 500", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su acceso", claimsChannel: "soporte@easysign.test" }, "v1");

test("the type comes from the bytes: PDF, PNG, JPEG and UTF-8 text pass; executables and binaries do not", () => {
  assert.equal(detectType(PDF), "application/pdf");
  assert.equal(detectType(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0])), "image/png");
  assert.equal(detectType(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0])), "image/jpeg");
  assert.equal(detectType(Buffer.from("contrato de arrendamiento ñ")), "text/plain");
  assert.equal(detectType(Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03])), undefined); // MZ executable
  assert.equal(detectType(Buffer.from([0x68, 0x00, 0x69])), undefined); // NUL byte
  assert.equal(detectType(Buffer.from([0xc3, 0x28])), undefined); // invalid UTF-8
});

test("the store is content addressed, bounded, and detects tampering on disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "easysign-docs-"));
  const store = new DocumentStore(dir);
  const put = store.put(PDF);
  assert.equal(put.hash, PDF_HASH);
  assert.deepEqual(readdirSync(dir), [PDF_HASH]);
  assert.deepEqual(store.get(PDF_HASH).bytes, PDF);
  assert.throws(() => store.put(Buffer.alloc(0)), code("EMPTY"));
  assert.throws(() => store.put(Buffer.alloc(MAX_DOCUMENT_BYTES + 1, 0x41)), code("TOO_LARGE"));
  assert.throws(() => store.put(Buffer.from([0x4d, 0x5a, 0x90, 0x00])), code("UNSUPPORTED_TYPE"));
  assert.throws(() => store.get("../../etc/passwd"), code("NOT_FOUND"));
  writeFileSync(join(dir, PDF_HASH), "%PDF-1.4 altered");
  assert.throws(() => store.get(PDF_HASH), code("NOT_FOUND")); // bytes no longer match their hash
  assert.equal(safeFileName("../../etc/passwd.pdf", "application/pdf"), "etc_passwd.pdf");
  assert.equal(safeFileName(undefined, "image/png"), "documento.png");
});

test("workflow: a document can only be attached to a draft, and signing needs the signer to have opened it", () => {
  const w = new SignatureWorkflow();
  const r = w.create({ tenantId: "t1", documentName: "C", documentHash: PDF_HASH, signers: [{ name: "A", email: "a@x.test" }] }, "x");
  assert.throws(() => w.documentAccess(r.id, r.signers[0].id, "x".repeat(43)), code("INVALID_STATE")); // a draft has no live links yet
  w.attachDocument(r.id, { contentType: "application/pdf", size: PDF.length, fileName: "c.pdf" });
  const [t] = w.send(r.id).tokens;
  assert.throws(() => w.attachDocument(r.id, { contentType: "application/pdf", size: 1, fileName: "c.pdf" }), code("INVALID_STATE"));

  w.view(r.id, t.signerId, t.token);
  assert.throws(() => w.consent(r.id, t.signerId, t.token, "d".repeat(64), "d".repeat(64), {}), code("INVALID_STATE")); // not opened yet
  assert.equal(w.documentAccess(r.id, t.signerId, t.token).fileName, "c.pdf");
  w.documentAccess(r.id, t.signerId, t.token); // opening twice records once
  w.consent(r.id, t.signerId, t.token, "d".repeat(64), "d".repeat(64), {});
  w.sign(r.id, t.signerId, t.token, PDF_HASH, {});
  assert.deepEqual(w.evidence(r.id).events.map((e) => e.type), ["created", "document_attached", "sent", "viewed", "document_viewed", "consented", "signed", "completed"]);
  assert.ok(w.get(r.id).signers[0].documentViewedAt);

  const none = new SignatureWorkflow();
  const r2 = none.create({ tenantId: "t1", documentName: "C", documentHash: PDF_HASH, signers: [{ name: "A", email: "a@x.test" }] }, "x");
  const [t2] = none.send(r2.id).tokens;
  assert.throws(() => none.documentAccess(r2.id, t2.signerId, t2.token), code("INVALID_STATE"));
});

test("API: upload is checked against the hash, the signer must open the document, and bytes come back intact and sandboxed", async () => {
  const audit = new AuditLog();
  const app = buildApp({ registryAdminToken: "tok", disclosure: DISCLOSURE, publicBaseUrl: "https://firma.example.test", auditLog: audit, workflow: new SignatureWorkflow(), documents: new DocumentStore() });
  const h = { authorization: "Bearer tok" };
  const make = async () => (await app.inject({ method: "POST", url: "/v1/signature-workflows", headers: h, payload: { tenantId: "t1", documentName: "Contrato", documentHash: PDF_HASH, signers: [{ name: "Ana", email: "ana@x.test" }] } })).json().id as string;
  const id = await make();

  // cannot be sent without a document unless the administrator explicitly accepts that
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: h })).json().error, "DOCUMENT_REQUIRED");

  const put = (body: Buffer, type = "application/pdf", headers = h) => app.inject({ method: "PUT", url: `/v1/signature-workflows/${id}/document`, headers: { ...headers, "content-type": type, "x-file-name": "../Contrato final.pdf" }, payload: body });
  assert.equal((await put(PDF, "application/pdf", {} as never)).statusCode, 401);
  assert.equal((await put(Buffer.from("%PDF-1.4 other file"))).statusCode, 409); // hash mismatch
  assert.equal((await put(Buffer.from([0x4d, 0x5a, 0x90, 0x00]), "application/octet-stream")).statusCode, 400); // executable
  assert.equal((await put(Buffer.alloc(MAX_DOCUMENT_BYTES + 10, 0x41), "text/plain")).statusCode, 413);
  const ok = await put(PDF);
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().document.fileName, "Contrato_final.pdf");

  const sent = (await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/send`, headers: h })).json();
  const a = sent.tokens[0];
  const base = `/v1/signature-workflows/${id}/signers/${a.signerId}`;
  const view = (await app.inject({ method: "POST", url: `${base}/view`, payload: { token: a.token } })).json();
  assert.equal(view.document.contentType, "application/pdf");
  assert.equal(view.documentViewed, false);

  // accepting before opening the document is refused, and so is a wrong token on the document route
  assert.equal((await app.inject({ method: "POST", url: `${base}/consent`, payload: { token: a.token, disclosureHash: DISCLOSURE.hash } })).statusCode, 409);
  assert.equal((await app.inject({ method: "POST", url: `${base}/document`, payload: { token: "w".repeat(43) } })).statusCode, 401);

  const doc = await app.inject({ method: "POST", url: `${base}/document`, payload: { token: a.token } });
  assert.equal(doc.statusCode, 200);
  assert.equal(doc.headers["content-type"], "application/pdf");
  assert.match(String(doc.headers["content-security-policy"]), /sandbox/);
  assert.equal(doc.headers["x-content-type-options"], "nosniff");
  assert.deepEqual(doc.rawPayload, PDF);

  assert.equal((await app.inject({ method: "POST", url: `${base}/consent`, payload: { token: a.token, disclosureHash: DISCLOSURE.hash } })).statusCode, 200);
  assert.equal((await app.inject({ method: "POST", url: `${base}/sign`, payload: { token: a.token, documentHash: PDF_HASH } })).json().status, "completed");

  const ev = (await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}/evidence`, headers: h })).json();
  assert.ok(ev.request.signers[0].documentViewedAt);
  assert.ok(ev.events.some((e: { type: string }) => e.type === "document_viewed"));
  assert.ok(!JSON.stringify((await audit.query())).includes("%PDF"), "document bytes never reach the audit ledger");

  // explicit acknowledgement lets a request go out without a document
  const id2 = await make();
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id2}/send`, headers: h, payload: { acknowledgeNoDocument: true } })).statusCode, 200);
});
