import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { SignJWT, UnsecuredJWT, createLocalJWKSet, exportJWK, generateKeyPair } from "jose";
import { CompositeAuthenticator, OidcAuthenticator, authenticatorFromEnv } from "./auth/guard.js";
import { AuditLog } from "./services/audit-log.js";
import { SignatureWorkflow } from "./services/signature-workflow.js";
import { buildApp } from "./app.js";

const ISS = "https://idp.test/realms/easysign";
const AUD = "easysign-api";
const DOC = createHash("sha256").update("contrato").digest("hex");
const CERT = { serial: "AB12", subject: "CN=a", issuer: "CN=b", notBefore: "2026-01-01T00:00:00.000Z", notAfter: "2027-01-01T00:00:00.000Z" };

async function idp() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" }] });
  const authenticator = new CompositeAuthenticator(new OidcAuthenticator({ issuer: ISS, audience: AUD, jwks }), undefined);
  const now = () => Math.floor(Date.now() / 1000);
  const token = (claims: Record<string, unknown>, o: { iss?: string; aud?: string; exp?: number; key?: CryptoKey; sub?: string } = {}) =>
    new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(o.iss ?? ISS).setAudience(o.aud ?? AUD).setSubject(o.sub ?? "user-1").setIssuedAt().setExpirationTime(o.exp ?? now() + 300).sign(o.key ?? privateKey);
  const as = async (roles: string[], tenant?: string, sub = "user-1") => ({ authorization: `Bearer ${await token({ roles, ...(tenant ? { tenant_id: tenant } : {}) }, { sub })}` });
  return { authenticator, token, as, privateKey, now };
}

test("OIDC tokens: only valid, correctly signed tokens with a known role pass", async () => {
  const { authenticator, token, as, now } = await idp();
  const app = buildApp({ registryAdminToken: undefined, authenticator });
  const write = (headers?: Record<string, string>) => app.inject({ method: "POST", url: "/v1/registry/certificates", headers, payload: CERT });

  assert.equal((await write(await as(["platform_admin"]))).statusCode, 201);
  assert.equal((await write(await as(["tenant_admin"], "t1"))).statusCode, 403); // wrong role for a platform-level action
  assert.equal((await write(await as(["superuser"]))).statusCode, 403); // unknown roles grant nothing
  assert.equal((await write(await as([]))).statusCode, 403);
  assert.equal((await write()).statusCode, 401);
  assert.equal((await write({ authorization: "Bearer not-a-token" })).statusCode, 401);

  const bad = async (t: Promise<string>) => (await write({ authorization: `Bearer ${await t}` })).statusCode;
  assert.equal(await bad(token({ roles: ["platform_admin"] }, { exp: now() - 3600 })), 401); // expired
  assert.equal(await bad(token({ roles: ["platform_admin"] }, { aud: "other-api" })), 401); // wrong audience
  assert.equal(await bad(token({ roles: ["platform_admin"] }, { iss: "https://evil.test" })), 401); // wrong issuer
  const other = await generateKeyPair("RS256");
  assert.equal(await bad(token({ roles: ["platform_admin"] }, { key: other.privateKey })), 401); // signed by an unknown key
  assert.equal(await bad(Promise.resolve(new UnsecuredJWT({ roles: ["platform_admin"] }).setIssuer(ISS).setAudience(AUD).setSubject("x").encode())), 401); // alg "none"
  assert.equal(await bad(new SignJWT({ roles: ["platform_admin"] }).setProtectedHeader({ alg: "HS256" }).setIssuer(ISS).setAudience(AUD).setSubject("x").setExpirationTime("5m").sign(new TextEncoder().encode("a-shared-secret-of-sufficient-length-123456"))), 401); // HMAC key confusion
});

test("tenant isolation on signature workflows: own tenant yes, another tenant looks like it does not exist", async () => {
  const { authenticator, as } = await idp();
  const app = buildApp({ registryAdminToken: undefined, authenticator, workflow: new SignatureWorkflow(), auditLog: new AuditLog() });
  const body = (tenantId: string) => ({ tenantId, documentName: "Contrato", documentHash: DOC, signers: [{ name: "Ana", email: `ana@${tenantId}.test` }] });
  const create = (h: Record<string, string>, tenantId: string) => app.inject({ method: "POST", url: "/v1/signature-workflows", headers: h, payload: body(tenantId) });

  const adminA = await as(["tenant_admin"], "tenant-a");
  const created = await create(adminA, "tenant-a");
  assert.equal(created.statusCode, 201);
  const id = created.json().id;

  assert.equal((await create(adminA, "tenant-b")).statusCode, 403); // cannot create for another tenant
  assert.equal((await create(await as(["tenant_admin"]), "tenant-a")).statusCode, 403); // a token without a tenant matches none
  assert.equal((await create(await as(["auditor"], "tenant-a"), "tenant-a")).statusCode, 403); // auditors are read-only

  const adminB = await as(["tenant_admin"], "tenant-b");
  assert.equal((await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}`, headers: adminB })).statusCode, 404); // another tenant's request is invisible
  assert.equal((await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}/evidence`, headers: adminB })).statusCode, 404);
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/cancel`, headers: adminB, payload: {} })).statusCode, 404);
  assert.equal((await app.inject({ method: "GET", url: "/v1/signature-workflows/does-not-exist", headers: adminB })).statusCode, 404); // same answer as an unknown id

  assert.equal((await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}`, headers: adminA })).statusCode, 200);
  assert.equal((await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}/evidence`, headers: await as(["auditor"], "tenant-a") })).statusCode, 200); // auditor reads own tenant
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/cancel`, headers: await as(["auditor"], "tenant-a"), payload: {} })).statusCode, 403);
  assert.equal((await app.inject({ method: "GET", url: `/v1/signature-workflows/${id}`, headers: await as(["platform_admin"]) })).statusCode, 200); // platform sees every tenant
  assert.equal((await app.inject({ method: "POST", url: `/v1/signature-workflows/${id}/cancel`, headers: await as(["tenant_operator"], "tenant-a"), payload: { reason: "ok" } })).statusCode, 200);
});

test("tenant isolation on consents and the audit ledger; the actor is the token's subject", async () => {
  const { authenticator, as } = await idp();
  const audit = new AuditLog();
  const app = buildApp({ registryAdminToken: undefined, authenticator, auditLog: audit });
  const grant = (h: Record<string, string>, tenantId: string, subjectId = "s1") => app.inject({ method: "POST", url: "/v1/consents", headers: h, payload: { tenantId, subjectId, purpose: "marketing", textVersion: "v1", text: "acepto", evidence: { channel: "web" } } });

  const adminA = await as(["tenant_admin"], "tenant-a", "alice");
  assert.equal((await grant(adminA, "tenant-a")).statusCode, 201);
  assert.equal((await grant(adminA, "tenant-b")).statusCode, 403);
  assert.equal((await grant(await as(["platform_admin"], undefined, "root"), "tenant-b")).statusCode, 201);

  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/tenant-a/s1", headers: adminA })).json().marketingAllowed, true);
  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/tenant-b/s1", headers: adminA })).statusCode, 403);
  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/tenant-a/s1", headers: await as(["auditor"], "tenant-a") })).statusCode, 200);

  // the audit ledger: tenant roles only ever see their own tenant, whatever they ask for
  const mine = (await app.inject({ method: "GET", url: "/v1/audit/events?tenantId=tenant-b", headers: adminA })).json();
  assert.ok(mine.events.length > 0);
  assert.ok(mine.events.every((e: { tenantId: string }) => e.tenantId === "tenant-a"));
  const all = (await app.inject({ method: "GET", url: "/v1/audit/events", headers: await as(["platform_admin"]) })).json();
  assert.ok(all.events.some((e: { tenantId: string }) => e.tenantId === "tenant-b"));
  assert.equal((await app.inject({ method: "POST", url: "/v1/audit/export", headers: adminA, payload: { tenantId: "tenant-b" } })).statusCode, 403);
  assert.equal((await app.inject({ method: "POST", url: "/v1/audit/export", headers: adminA, payload: { tenantId: "tenant-a" } })).statusCode, 200);
  assert.equal((await app.inject({ method: "GET", url: "/v1/audit/events", headers: await as(["tenant_operator"], "tenant-a") })).statusCode, 403); // operators do not read the ledger

  assert.ok((await audit.query({ tenantId: "tenant-a" })).some((e) => e.actor === "alice" && e.outcome === "success"));
  assert.ok((await audit.query({ tenantId: "tenant-b" })).some((e) => e.actor === "root"));
  assert.ok((await audit.query()).some((e) => e.outcome === "denied" && e.tenantId === "tenant-a"), "denied cross-tenant attempts are audited");
});

test("configuration: OIDC turns the static token off unless break-glass is on; nothing configured fails closed", async () => {
  const env = { EASYSIGN_OIDC_ISSUER: ISS, EASYSIGN_OIDC_AUDIENCE: AUD, EASYSIGN_OIDC_JWKS_URI: "https://idp.test/certs" };
  const strict = authenticatorFromEnv(env, "static-secret");
  assert.equal(await strict?.authenticate("Bearer static-secret"), undefined);
  const breakGlass = authenticatorFromEnv({ ...env, EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN: "true" }, "static-secret");
  assert.deepEqual((await breakGlass?.authenticate("Bearer static-secret"))?.roles, ["platform_admin"]);
  assert.equal(await breakGlass?.authenticate("Bearer wrong"), undefined);
  const staticOnly = authenticatorFromEnv({}, "static-secret");
  assert.equal((await staticOnly?.authenticate("Bearer static-secret"))?.via, "static");
  assert.equal(authenticatorFromEnv({}, undefined), undefined);

  const closed = buildApp({ registryAdminToken: undefined });
  assert.equal((await closed.inject({ method: "POST", url: "/v1/registry/certificates", payload: CERT })).statusCode, 503);
  assert.equal((await closed.inject({ method: "GET", url: "/v1/registry/certificates" })).statusCode, 200); // public reads stay public
});

test("Keycloak-style nested role claims and space-separated roles are understood", async () => {
  const { privateKey } = await generateKeyPair("RS256");
  const pair = await generateKeyPair("RS256");
  const jwks = createLocalJWKSet({ keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k2", alg: "RS256" }] });
  const sign = (claims: Record<string, unknown>) => new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k2" }).setIssuer(ISS).setAudience(AUD).setSubject("kc-user").setExpirationTime("5m").sign(pair.privateKey);
  void privateKey;
  const nested = new OidcAuthenticator({ issuer: ISS, audience: AUD, jwks, rolesClaim: "realm_access.roles", tenantClaim: "org.tenant" });
  const p = await nested.authenticate(`Bearer ${await sign({ realm_access: { roles: ["tenant_admin", "offline_access"] }, org: { tenant: "t9" } })}`);
  assert.deepEqual(p?.roles, ["tenant_admin"]);
  assert.equal(p?.tenantId, "t9");
  const spaced = new OidcAuthenticator({ issuer: ISS, audience: AUD, jwks });
  assert.deepEqual((await spaced.authenticate(`Bearer ${await sign({ roles: "auditor tenant_operator" })}`))?.roles, ["auditor", "tenant_operator"]);
});
