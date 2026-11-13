import { timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

/**
 * Authentication (OIDC access tokens, or the legacy static admin token) and role-based authorization with tenant
 * isolation (backlog ES-005). Everything fails closed: with no authenticator configured every protected call is 503.
 *
 * Roles: platform_admin (everything, all tenants), tenant_admin and tenant_operator (read/write inside their own tenant),
 * auditor (read-only inside their own tenant). Tenant roles carry the tenant in a token claim; without it they match no tenant.
 */

export type Role = "platform_admin" | "tenant_admin" | "tenant_operator" | "auditor";
export const ALL_ROLES: readonly Role[] = ["platform_admin", "tenant_admin", "tenant_operator", "auditor"];
export const WRITERS: Role[] = ["platform_admin", "tenant_admin", "tenant_operator"];
export const READERS: Role[] = ["platform_admin", "tenant_admin", "tenant_operator", "auditor"];

export interface Principal {
  sub: string;
  roles: Role[];
  tenantId?: string;
  via: "oidc" | "static";
}

declare module "fastify" {
  interface FastifyRequest { principal?: Principal }
}

export interface Authenticator {
  isConfigured(): boolean;
  /** Resolves to a principal, or undefined for any invalid credential (the reason is never revealed to the caller). */
  authenticate(authorization: string | undefined): Promise<Principal | undefined>;
}

const bearer = (header: string | undefined) => String(header ?? "").replace(/^Bearer\s+/i, "").trim();
const looksLikeJwt = (token: string) => token.split(".").length === 3 && token.length > 20;

export class StaticTokenAuthenticator implements Authenticator {
  constructor(private readonly token: string | undefined) {}
  isConfigured() { return Boolean(this.token); }
  async authenticate(authorization: string | undefined): Promise<Principal | undefined> {
    if (!this.token) return undefined;
    const given = Buffer.from(bearer(authorization));
    const expected = Buffer.from(this.token);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return undefined;
    return { sub: "static-admin", roles: ["platform_admin"], via: "static" };
  }
}

export interface OidcOptions {
  issuer: string;
  audience: string;
  jwks: JWTVerifyGetKey;
  /** Dotted path to the roles claim, e.g. "roles" or "realm_access.roles" (Keycloak). */
  rolesClaim?: string;
  tenantClaim?: string;
  clockToleranceSec?: number;
}

const claimAt = (payload: JWTPayload, path: string): unknown => path.split(".").reduce<unknown>((acc, key) => (acc && typeof acc === "object" ? (acc as Record<string, unknown>)[key] : undefined), payload);

export class OidcAuthenticator implements Authenticator {
  constructor(private readonly o: OidcOptions) {}
  isConfigured() { return true; }
  async authenticate(authorization: string | undefined): Promise<Principal | undefined> {
    const token = bearer(authorization);
    if (!looksLikeJwt(token)) return undefined;
    try {
      // asymmetric algorithms only: "none" and HMAC (key-confusion) tokens are refused
      const { payload } = await jwtVerify(token, this.o.jwks, { issuer: this.o.issuer, audience: this.o.audience, algorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"], clockTolerance: this.o.clockToleranceSec ?? 30 });
      if (typeof payload.sub !== "string" || !payload.sub) return undefined;
      const raw = claimAt(payload, this.o.rolesClaim ?? "roles");
      const list = Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(/\s+/) : [];
      const roles = list.filter((r): r is Role => ALL_ROLES.includes(r as Role));
      const tenant = claimAt(payload, this.o.tenantClaim ?? "tenant_id");
      return { sub: payload.sub, roles, tenantId: typeof tenant === "string" && tenant ? tenant : undefined, via: "oidc" };
    } catch {
      return undefined;
    }
  }
}

/** OIDC tokens (three dot-separated parts) go to the OIDC authenticator; anything else to the static one. */
export class CompositeAuthenticator implements Authenticator {
  constructor(private readonly oidc: OidcAuthenticator | undefined, private readonly staticToken: StaticTokenAuthenticator | undefined) {}
  isConfigured() { return Boolean(this.oidc?.isConfigured() || this.staticToken?.isConfigured()); }
  async authenticate(authorization: string | undefined): Promise<Principal | undefined> {
    if (this.oidc && looksLikeJwt(bearer(authorization))) return this.oidc.authenticate(authorization);
    return this.staticToken?.authenticate(authorization);
  }
}

export interface AuthEnv {
  EASYSIGN_OIDC_ISSUER?: string;
  EASYSIGN_OIDC_AUDIENCE?: string;
  EASYSIGN_OIDC_JWKS_URI?: string;
  EASYSIGN_OIDC_ROLES_CLAIM?: string;
  EASYSIGN_OIDC_TENANT_CLAIM?: string;
  EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN?: string;
}

/**
 * OIDC is enabled when issuer, audience and JWKS URI are all set. When it is enabled the static admin token is OFF unless
 * EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN=true (break-glass). With neither configured there is no authenticator (everything 503).
 */
export function authenticatorFromEnv(env: AuthEnv, staticToken: string | undefined): Authenticator | undefined {
  const oidc = env.EASYSIGN_OIDC_ISSUER && env.EASYSIGN_OIDC_AUDIENCE && env.EASYSIGN_OIDC_JWKS_URI
    ? new OidcAuthenticator({ issuer: env.EASYSIGN_OIDC_ISSUER, audience: env.EASYSIGN_OIDC_AUDIENCE, jwks: createRemoteJWKSet(new URL(env.EASYSIGN_OIDC_JWKS_URI)), rolesClaim: env.EASYSIGN_OIDC_ROLES_CLAIM, tenantClaim: env.EASYSIGN_OIDC_TENANT_CLAIM })
    : undefined;
  const staticAuth = staticToken && (!oidc || env.EASYSIGN_ALLOW_STATIC_ADMIN_TOKEN === "true") ? new StaticTokenAuthenticator(staticToken) : undefined;
  if (!oidc && !staticAuth) return undefined;
  return new CompositeAuthenticator(oidc, staticAuth);
}

export class Guard {
  constructor(private readonly authenticator: Authenticator | undefined) {}

  /**
   * Authenticates and authorizes. Sends the error response itself and returns undefined when access is refused.
   * `tenantId`: when given, a non-platform principal must belong to that tenant. `hideForeign` answers 404 instead of 403
   * for another tenant's resource so ids of other tenants are not confirmed to exist.
   */
  async require(request: FastifyRequest, reply: FastifyReply, roles: readonly Role[], tenantId?: string, hideForeign = false): Promise<Principal | undefined> {
    if (!this.authenticator?.isConfigured()) { reply.code(503).send({ error: "ADMIN_AUTH_NOT_CONFIGURED" }); return undefined; }
    const p = await this.authenticator.authenticate(request.headers.authorization);
    if (!p) { reply.code(401).send({ error: "UNAUTHORIZED" }); return undefined; }
    request.principal = p;
    if (!p.roles.some((r) => roles.includes(r))) { reply.code(403).send({ error: "FORBIDDEN", message: "Your role does not allow this action." }); return undefined; }
    if (tenantId !== undefined && !p.roles.includes("platform_admin") && (!p.tenantId || p.tenantId !== tenantId)) {
      if (hideForeign) reply.code(404).send({ error: "NOT_FOUND" });
      else reply.code(403).send({ error: "FORBIDDEN", message: "This resource belongs to another tenant." });
      return undefined;
    }
    return p;
  }
}

/** tenantId of a JSON body, or "" (matches no tenant) when missing, so tenant roles are refused rather than let through. */
export const tenantOf = (body: unknown): string => (body && typeof body === "object" && typeof (body as { tenantId?: unknown }).tenantId === "string" ? (body as { tenantId: string }).tenantId : "");
