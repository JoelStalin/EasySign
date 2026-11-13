import test from "node:test";
import assert from "node:assert/strict";
import { AuditLog } from "./services/audit-log.js";
import { buildApp } from "./app.js";

const XML = "<ECF><Encabezado><IdDoc><eNCF>E310000000007</eNCF></IdDoc><Totales><MontoTotal>1500.00</MontoTotal></Totales></Encabezado></ECF>";

async function runJob(app: ReturnType<typeof buildApp>, operation: string, data: Record<string, unknown>, tenantId = "t1") {
  const res = await app.inject({ method: "POST", url: "/v1/transactions/async", payload: { tenantId, operation, data } });
  assert.equal(res.statusCode, 202);
  const id = res.json().jobId ?? res.json().id;
  for (let i = 0; i < 100; i++) {
    const j = (await app.inject({ method: "GET", url: `/v1/jobs/${id}` })).json();
    if (j.status === "completed" || j.status === "failed") return j;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("job did not finish");
}

test("verify_signature really verifies: a signed document passes and a tampered one fails", async () => {
  const app = buildApp({ registryAdminToken: undefined, auditLog: new AuditLog() });
  const signed = await runJob(app, "sign_ecf_xml", { documentId: "d1", tenantId: "t1", rncEmisor: "101000019", eNcf: "E310000000007", rawXml: XML });
  assert.equal(signed.status, "completed");
  const signedXml: string = signed.result.signedXml;

  const ok = await runJob(app, "verify_signature", { signedXml });
  assert.equal(ok.result.verified, true);
  assert.equal(ok.result.validationProfile, "XMLDSIG_CRYPTOGRAPHIC_ONLY");

  const bad = await runJob(app, "verify_signature", { signedXml: signedXml.replace("1500.00", "9999.00") });
  assert.equal(bad.result.verified, false);
  assert.ok(bad.result.errors.length > 0);

  // the old behaviour accepted any long string as a "signature value"
  const fake = await runJob(app, "verify_signature", { signatureValue: "x".repeat(50) });
  assert.equal(fake.status, "failed");
  await app.close();
});

test("signing operations are written to the audit ledger without payloads", async () => {
  const audit = new AuditLog();
  const app = buildApp({ registryAdminToken: undefined, auditLog: audit });
  await runJob(app, "sign_ecf_xml", { documentId: "d2", tenantId: "t9", rncEmisor: "101000019", eNcf: "E310000000008", rawXml: XML }, "t9");
  await runJob(app, "verify_signature", { signatureValue: "short" }, "t9");
  const events = (await audit.query({ tenantId: "t9" }));
  assert.ok(events.some((e) => e.action === "job:sign_ecf_xml" && e.outcome === "success"));
  assert.ok(events.some((e) => e.action === "job:verify_signature" && e.outcome === "error"));
  assert.ok(!JSON.stringify(events).includes("E310000000008"), "document data is not stored");
  assert.equal(await audit.verifyChain(), true);
  await app.close();
});
