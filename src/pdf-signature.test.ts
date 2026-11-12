import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PDFDocument } from "pdf-lib";
import { SigningEngine } from "./services/signing-engine.js";
import { CertificateError, generateTestCertificate, loadPkcs12, toPkcs12 } from "./services/certificate-store.js";
import { PdfSignatureError, verifyPdfSignature } from "./services/pdf-signature.js";
import { AuditLog } from "./services/audit-log.js";
import { buildApp } from "./app.js";

async function makePdf(text = "Contrato de prueba EasySign - monto RD$ 1,500.00"): Promise<Buffer> {
  const doc = await PDFDocument.create();
  doc.addPage([300, 200]).drawText(text, { x: 20, y: 150, size: 10 });
  return Buffer.from(await doc.save());
}

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const req = (pdf: Buffer, over: Record<string, unknown> = {}) => ({ documentId: "d1", tenantId: "t1", pdfBase64: pdf.toString("base64"), signerName: "Ana Perez", signerEmail: "ana@x.test", ...over });
const flip = (pdf: Buffer, at: number) => {
  const copy = Buffer.from(pdf);
  copy[at] ^= 0x01;
  return copy;
};

test("a generated PDF is signed with PAdES (ETSI.CAdES.detached) and the signature verifies", async () => {
  const now = new Date("2026-11-12T15:04:05.678Z");
  const engine = new SigningEngine({ now: () => now });
  const pdf = await makePdf();
  const r = await engine.signPdf(req(pdf));
  const signed = Buffer.from(r.signedPdfBase64, "base64");

  assert.equal(r.testCertificate, true);
  assert.equal(r.subFilter, "ETSI.CAdES.detached");
  assert.equal(r.profile, "PAdES-B-B");
  assert.equal(r.trustedTimestamp, false);
  assert.equal(r.documentHash, sha256(pdf));
  assert.equal(r.signedDocumentHash, sha256(signed));
  assert.equal(r.signedAt, "2026-11-12T15:04:05.000Z");
  assert.ok(signed.includes("/SubFilter /ETSI.CAdES.detached"));
  assert.equal(r.byteRange[0], 0);
  assert.equal(r.byteRange[2] + r.byteRange[3], signed.length);

  const v = engine.verifyPdf(signed);
  assert.deepEqual(v.errors, []);
  assert.equal(v.valid, true);
  assert.equal(v.coversWholeDocument, true);
  assert.equal(v.subFilter, "ETSI.CAdES.detached");
  assert.equal(v.signingTime, r.signedAt);
  assert.equal(v.documentDigest, r.byteRangeDigest);
  assert.equal(v.digestAlgorithm, "sha256");
  assert.equal(v.certificate?.serial, r.certificateSerial);
  assert.match(v.certificate?.subject ?? "", /EasySign TEST/);
  assert.equal(v.trust, "NOT_EVALUATED");

  // the signed file is still a readable PDF with the original page
  assert.equal((await PDFDocument.load(signed)).getPageCount(), 1);
});

test("altering one byte inside the ByteRange makes verification fail", async () => {
  const engine = new SigningEngine({});
  const r = await engine.signPdf(req(await makePdf()));
  const signed = Buffer.from(r.signedPdfBase64, "base64");
  const [, firstLength, secondStart, secondLength] = r.byteRange;

  for (const at of [Math.floor(firstLength / 2), secondStart + Math.floor(secondLength / 2), signed.length - 1]) {
    const v = verifyPdfSignature(flip(signed, at));
    assert.equal(v.valid, false, `byte ${at}`);
    assert.ok(v.errors.some((e) => /digest does not match/.test(e)), `byte ${at}: ${v.errors.join("; ")}`);
  }
});

test("altering the signature value, appending content or stripping the signature is detected", async () => {
  const engine = new SigningEngine({});
  const r = await engine.signPdf(req(await makePdf()));
  const signed = Buffer.from(r.signedPdfBase64, "base64");

  // the RSA signature value sits at the end of the CMS, inside /Contents and outside the ByteRange
  const hex = signed.subarray(r.byteRange[1] + 1, r.byteRange[2] - 1).toString("latin1");
  const cmsHexLength = hex.replace(/0+$/, "").length;
  const at = r.byteRange[1] + 1 + cmsHexLength - 20;
  const forged = Buffer.from(signed);
  forged[at] = forged[at] === 0x61 ? 0x62 : 0x61; // 'a' <-> 'b', still valid hex
  const v1 = verifyPdfSignature(forged);
  assert.equal(v1.valid, false);
  assert.ok(v1.errors.some((e) => /signature value does not verify/.test(e)), v1.errors.join("; "));

  const appended = verifyPdfSignature(Buffer.concat([signed, Buffer.from("\n% contenido agregado despues de firmar\n")]));
  assert.equal(appended.valid, false);
  assert.equal(appended.coversWholeDocument, false);

  const unsigned = verifyPdfSignature(await makePdf());
  assert.equal(unsigned.valid, false);
  assert.match(unsigned.errors[0], /no signature/);
  assert.equal(verifyPdfSignature(Buffer.from("not a pdf")).valid, false);
});

test("production refuses to sign a PDF without a real certificate, with the test certificate or with an expired one", async () => {
  const pdf = await makePdf();
  const required = (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_REQUIRED";
  await assert.rejects(new SigningEngine({}).signPdf(req(pdf, { environment: "production" })), required);
  await assert.rejects(new SigningEngine({ certificate: generateTestCertificate() }).signPdf(req(pdf, { environment: "production" })), required);
  const expired = generateTestCertificate({ notBefore: new Date("2020-01-01"), notAfter: new Date("2021-01-01") });
  await assert.rejects(new SigningEngine({ certificate: expired }).signPdf(req(pdf)), (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_EXPIRED");
});

test("a PKCS#12 certificate signs a PDF for production; verification can pin the expected certificate", async () => {
  const source = generateTestCertificate();
  const real = loadPkcs12(toPkcs12(source, "correct-horse"), "correct-horse");
  const engine = new SigningEngine({ certificate: real });
  const r = await engine.signPdf(req(await makePdf(), { environment: "production", reason: "Aprobación del contrato Ñ-01", location: "Santo Domingo" }));
  assert.equal(r.testCertificate, false);
  assert.equal(r.certificateSerial, source.serial);

  const signed = Buffer.from(r.signedPdfBase64, "base64");
  assert.equal(engine.verifyPdf(signed, real.certificatePem).valid, true);
  const other = engine.verifyPdf(signed, generateTestCertificate().certificatePem);
  assert.equal(other.valid, false);
  assert.ok(other.errors.some((e) => /not the expected certificate/.test(e)));
});

test("invalid input is rejected: not a PDF, hash mismatch, missing payload, already signed", async () => {
  const engine = new SigningEngine({});
  const pdf = await makePdf();
  await assert.rejects(engine.signPdf(req(Buffer.from("hola, no soy un PDF"))), (e: unknown) => e instanceof PdfSignatureError && e.code === "PDF_INVALID");
  await assert.rejects(engine.signPdf(req(pdf, { documentHash: "0".repeat(64) })), /DOCUMENT_MISMATCH/);
  await assert.rejects(engine.signPdf(req(pdf, { pdfBase64: undefined })), /pdfBase64/);
  assert.equal((await engine.signPdf(req(pdf, { documentHash: sha256(pdf) }))).documentHash, sha256(pdf));

  const once = await engine.signPdf(req(pdf));
  await assert.rejects(engine.signPdf(req(Buffer.from(once.signedPdfBase64, "base64"))), (e: unknown) => e instanceof PdfSignatureError && e.code === "PDF_ALREADY_SIGNED");
});

test("sign_pdf and verify_signature jobs sign and verify a PDF end to end", async () => {
  const app = buildApp({ registryAdminToken: undefined, auditLog: new AuditLog() });
  const runJob = async (operation: string, data: Record<string, unknown>) => {
    const res = await app.inject({ method: "POST", url: "/v1/transactions/async", payload: { tenantId: "t1", operation, data } });
    assert.equal(res.statusCode, 202);
    for (let i = 0; i < 200; i++) {
      const j = (await app.inject({ method: "GET", url: `/v1/jobs/${res.json().jobId}` })).json();
      if (j.status === "completed" || j.status === "failed") return j;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error("job did not finish");
  };

  const signed = await runJob("sign_pdf", req(await makePdf()));
  assert.equal(signed.status, "completed");
  assert.equal(signed.result.profile, "PAdES-B-B");

  const ok = await runJob("verify_signature", { signedPdfBase64: signed.result.signedPdfBase64 });
  assert.equal(ok.result.verified, true);
  assert.equal(ok.result.validationProfile, "PADES_CRYPTOGRAPHIC_ONLY");
  assert.equal(ok.result.signingTime, signed.result.signedAt);

  const tampered = flip(Buffer.from(signed.result.signedPdfBase64, "base64"), 40);
  const bad = await runJob("verify_signature", { signedPdfBase64: tampered.toString("base64") });
  assert.equal(bad.result.verified, false);
  assert.ok(bad.result.errors.length > 0);

  const prod = await runJob("sign_pdf", req(await makePdf(), { environment: "production" }));
  assert.equal(prod.status, "failed");
  await app.close();
});

const hasOpenssl = spawnSync("openssl", ["version"]).status === 0;
test("the CMS inside the PDF verifies with OpenSSL (independent implementation)", { skip: hasOpenssl ? false : "openssl is not installed" }, async () => {
  const r = await new SigningEngine({}).signPdf(req(await makePdf()));
  const signed = Buffer.from(r.signedPdfBase64, "base64");
  const [, b, c, d] = r.byteRange;
  const dir = mkdtempSync(join(tmpdir(), "easysign-pades-"));
  try {
    writeFileSync(join(dir, "content.bin"), Buffer.concat([signed.subarray(0, b), signed.subarray(c, c + d)]));
    const padded = Buffer.from(signed.subarray(b + 1, c - 1).toString("latin1"), "hex");
    const derLength = 4 + padded.readUInt16BE(2); // 30 82 LL LL
    writeFileSync(join(dir, "sig.der"), padded.subarray(0, derLength));
    // -noverify: the test certificate is self-signed; only the signature and the digest are checked
    const run = (content: string) => spawnSync("openssl", ["cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", join(dir, "sig.der"), "-content", join(dir, content), "-out", join(dir, "out.bin")], { encoding: "utf8" });
    const ok = run("content.bin");
    assert.equal(ok.status, 0, ok.stderr);
    writeFileSync(join(dir, "other.bin"), "otro contenido");
    assert.notEqual(run("other.bin").status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
