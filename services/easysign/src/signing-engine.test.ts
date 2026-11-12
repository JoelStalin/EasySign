import test from "node:test";
import assert from "node:assert/strict";
import { SigningEngine } from "./services/signing-engine.js";
import { CertificateError, generateTestCertificate, loadPkcs12, toPkcs12 } from "./services/certificate-store.js";

const XML = "<ECF><Encabezado><IdDoc><eNCF>E310000000001</eNCF></IdDoc><Totales><MontoTotal>1500.00</MontoTotal></Totales></Encabezado></ECF>";
const req = (over: Record<string, unknown> = {}) => ({ documentId: "d1", tenantId: "t1", rncEmisor: "101000019", eNcf: "E310000000001", rawXml: XML, ...over });

test("test environment signs with an ephemeral test certificate and the signature verifies", async () => {
  const engine = new SigningEngine({});
  const r = await engine.signEcfXml(req());
  assert.equal(r.testCertificate, true);
  assert.match(r.certificateIssuer, /TEST/);
  assert.ok(r.signedXml.includes("<X509Certificate>"));
  assert.equal(r.securityCode, r.signatureValue.slice(0, 6));
  assert.equal(r.securityCode.length, 6);
  assert.deepEqual(engine.verifyEcfXml(r.signedXml), { valid: true, errors: [] });
});

test("a tampered document no longer verifies", async () => {
  const engine = new SigningEngine({});
  const r = await engine.signEcfXml(req());
  const tampered = r.signedXml.replace("1500.00", "9500.00");
  const v = engine.verifyEcfXml(tampered);
  assert.equal(v.valid, false);
  assert.ok(v.errors.length > 0);
});

test("a signature checked against a different certificate is rejected", async () => {
  const engine = new SigningEngine({});
  const r = await engine.signEcfXml(req());
  const other = generateTestCertificate();
  assert.equal(engine.verifyEcfXml(r.signedXml, other.certificatePem).valid, false);
});

test("production refuses to sign without a real certificate", async () => {
  await assert.rejects(new SigningEngine({}).signEcfXml(req({ environment: "production" })), (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_REQUIRED");
});

test("production refuses the test certificate", async () => {
  const engine = new SigningEngine({ certificate: generateTestCertificate() });
  await assert.rejects(engine.signEcfXml(req({ environment: "production" })), (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_REQUIRED");
});

test("an expired certificate is refused", async () => {
  const expired = generateTestCertificate({ notBefore: new Date("2020-01-01"), notAfter: new Date("2021-01-01") });
  await assert.rejects(new SigningEngine({ certificate: expired }).signEcfXml(req()), (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_EXPIRED");
});

test("a PKCS#12 certificate loads, signs for production and verifies; a wrong passphrase fails without leaking it", async () => {
  const source = generateTestCertificate();
  const p12 = toPkcs12(source, "correct-horse");
  const real = loadPkcs12(p12, "correct-horse"); // loaded bundles are treated as real certificates
  assert.equal(real.isTest, false);
  assert.equal(real.serial, source.serial);

  const engine = new SigningEngine({ certificate: real });
  const r = await engine.signEcfXml(req({ environment: "production" }));
  assert.equal(r.testCertificate, false);
  assert.equal(r.certificateSerial, source.serial);
  assert.equal(engine.verifyEcfXml(r.signedXml).valid, true);

  assert.throws(() => loadPkcs12(p12, "wrong-pass"), (e: unknown) => e instanceof CertificateError && e.code === "CERTIFICATE_INVALID" && !String(e.message).includes("wrong-pass"));
});

test("malformed rawXml is rejected", async () => {
  await assert.rejects(new SigningEngine({}).signEcfXml(req({ rawXml: "not xml <<<" })));
});
