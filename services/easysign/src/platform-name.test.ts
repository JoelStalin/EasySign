import test from "node:test";
import assert from "node:assert/strict";
import { buildServiceDisclosure, DisclosureError } from "./services/legal-notices.js";
import { buildApp } from "./app.js";

const CFG = { providerName: "GetUpSoft SRL", rnc: "101000019", address: "Santo Domingo", serviceDescription: "Firma electrónica", certificateFeatures: "Uso general", liabilityLimitations: "Contrato", prices: "RD$ 500", serviceLevels: "99.5 %", subscriberObligations: "Custodiar su acceso", claimsChannel: "soporte@easysign.test" };

test("the platform brand is optional, validated, and changes the disclosure hash", () => {
  const plain = buildServiceDisclosure(CFG, "v1");
  const branded = buildServiceDisclosure({ ...CFG, platformName: "EasySign" }, "v1");
  assert.equal(branded.config.platformName, "EasySign");
  assert.notEqual(branded.hash, plain.hash); // signers accept exactly the text that names the platform
  assert.throws(() => buildServiceDisclosure({ ...CFG, platformName: "Entidad de Certificación Easy" }, "v1"), DisclosureError);
  assert.throws(() => buildServiceDisclosure({ ...CFG, platformName: "  " }, "v1"), DisclosureError);
  assert.throws(() => buildServiceDisclosure({ ...CFG, platformName: "x".repeat(81) }, "v1"), DisclosureError);
});

test("the public disclosure and the signing page name the platform and the company that operates it", async () => {
  const app = buildApp({ registryAdminToken: undefined, disclosure: buildServiceDisclosure({ ...CFG, platformName: "EasySign" }, "v1") });
  const d = (await app.inject({ method: "GET", url: "/v1/legal/disclosure" })).json();
  assert.equal(d.config.platformName, "EasySign");
  assert.equal(d.config.providerName, "GetUpSoft SRL");
  const js = (await app.inject({ method: "GET", url: "/sign/app.js" })).body;
  assert.ok(js.includes("operada por"));
  assert.ok(js.includes("cfg.rnc"));
});
