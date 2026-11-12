import { createHash } from "node:crypto";
import { FileLedgerStore, LedgerChainError, type LedgerDefinition, type LedgerRecord, type LedgerStore } from "../storage/ledger-store.js";

/**
 * Audit and evidence ledger (Res. INDOTEL 067-2025 Annex I art. 36.2 j: keep relevant records as legal evidence;
 * backlog ES-007). Append-only, SHA-256 hash-chained, with correlation IDs. Secrets are redacted before storage.
 * Events are kept in a LedgerStore: memory or a JSONL file by default, PostgreSQL with per-tenant row level
 * security when one is given (docs/POSTGRES_TENANCY.md).
 */

export interface AuditEvent {
  seq: number;
  at: string;
  correlationId: string;
  tenantId: string;
  actor: string;
  action: string;
  resource: string;
  outcome: "success" | "denied" | "error";
  details: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export type AuditInput = Omit<AuditEvent, "seq" | "at" | "prevHash" | "hash" | "details"> & { details?: Record<string, unknown> };

/** What an audit event stores besides the ledger envelope (seq, at, tenantId, hashes). */
export type AuditPayload = Pick<AuditEvent, "correlationId" | "actor" | "action" | "resource" | "outcome" | "details">;

export class AuditError extends Error {
  constructor(public readonly code: "CHAIN_BROKEN" | "INVALID_INPUT" | "TENANT_REQUIRED", message: string) {
    super(message);
    this.name = "AuditError";
  }
}

const SECRET_KEY = /pass(word|phrase)?|secret|token|authorization|private|p12|pfx|api[-_]?key|otp|cookie/i;
const MAX_STRING = 500;

/** Replaces values of secret-looking keys, recursively, and truncates long strings. */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, SECRET_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1)]));
  }
  return typeof value === "string" && value.length > MAX_STRING ? value.slice(0, MAX_STRING) + "…[TRUNCATED]" : value;
}

/** Keys sorted at every level and NUL characters removed: the only form that survives PostgreSQL `jsonb` unchanged. */
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(o).sort().map((k) => [k.replaceAll("\u0000", ""), sorted(o[k])]));
  }
  return typeof value === "string" ? value.replaceAll("\u0000", "") : value;
}

export const AUDIT_LEDGER: LedgerDefinition<AuditPayload> = {
  name: "audit",
  fixedType: "audit", // audit events have no type of their own; JSONL lines keep the original shape without it
  hash: (r) => createHash("sha256").update(JSON.stringify([r.seq, r.at, r.payload.correlationId, r.tenantId, r.payload.actor, r.payload.action, r.payload.resource, r.payload.outcome, r.payload.details, r.prevHash])).digest("hex"),
  canonical: (p) => {
    const x = p as unknown as AuditPayload;
    return { correlationId: x.correlationId, actor: x.actor, action: x.action, resource: x.resource, outcome: x.outcome, details: sorted(x.details ?? {}) as Record<string, unknown> };
  },
};

const toEvent = (r: LedgerRecord<AuditPayload>): AuditEvent => ({
  seq: r.seq, at: r.at, correlationId: r.payload.correlationId, tenantId: r.tenantId, actor: r.payload.actor, action: r.payload.action,
  resource: r.payload.resource, outcome: r.payload.outcome, details: r.payload.details, prevHash: r.prevHash, hash: r.hash,
});

const chainBroken = (e: unknown): never => {
  if (e instanceof LedgerChainError) throw new AuditError("CHAIN_BROKEN", `Audit event ${e.seq} does not match the hash chain: the ledger was altered.`);
  throw e;
};

export interface EvidencePackage {
  generatedAt: string;
  tenantId: string;
  eventCount: number;
  /** Hash of the last event of the whole ledger at export time, to anchor the package. */
  headHash: string;
  chainValid: boolean;
  events: AuditEvent[];
}

export interface AuditFilter { tenantId?: string; action?: string; correlationId?: string; from?: string; to?: string; limit?: number }

export class AuditLog {
  private readonly store: LedgerStore<AuditPayload>;
  private readonly now: () => Date;

  /** With `store` the ledger uses it; otherwise a JSONL file (`filePath`) or memory. A tampered file throws here. */
  constructor(options: { filePath?: string; store?: LedgerStore<AuditPayload>; now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
    try {
      this.store = options.store ?? new FileLedgerStore(AUDIT_LEDGER, { filePath: options.filePath });
    } catch (e) {
      throw chainBroken(e);
    }
  }

  public async record(input: AuditInput): Promise<AuditEvent> {
    if (!input.correlationId || !input.tenantId || !input.actor || !input.action) throw new AuditError("INVALID_INPUT", "correlationId, tenantId, actor and action are required.");
    const payload: AuditPayload = { correlationId: input.correlationId, actor: input.actor, action: input.action, resource: input.resource, outcome: input.outcome, details: redact(input.details ?? {}) as Record<string, unknown> };
    return toEvent(await this.store.append(input.tenantId, { type: "audit", at: this.now().toISOString(), payload }));
  }

  /**
   * Events of one tenant, or of every tenant when no tenant is given. On PostgreSQL the application role only ever
   * sees one tenant, so a query without tenant is refused there (TENANT_REQUIRED).
   */
  public async query(filter: AuditFilter = {}): Promise<AuditEvent[]> {
    let records: LedgerRecord<AuditPayload>[];
    try {
      if (filter.tenantId) records = await this.store.readAll(filter.tenantId);
      else if (this.store.readEverything) records = await this.store.readEverything();
      else throw new AuditError("TENANT_REQUIRED", "This audit ledger is isolated per tenant: a tenantId is required to read it.");
    } catch (e) {
      throw chainBroken(e);
    }
    return records.map(toEvent)
      .filter((e) => (!filter.action || e.action === filter.action) && (!filter.correlationId || e.correlationId === filter.correlationId)
        && (!filter.from || e.at >= filter.from) && (!filter.to || e.at <= filter.to))
      .slice(-Math.min(1000, filter.limit ?? 200));
  }

  /**
   * File or memory: verifies the whole chain. PostgreSQL: needs the tenant and verifies what that tenant can see;
   * the whole chain is verified with the auditor role (`npm run ledger:verify`).
   */
  public async verifyChain(tenantId?: string): Promise<boolean> {
    if (!tenantId && !this.store.readEverything) throw new AuditError("TENANT_REQUIRED", "This audit ledger is isolated per tenant: a tenantId is required to verify it.");
    return this.store.verify(tenantId);
  }

  public async exportEvidence(tenantId: string): Promise<EvidencePackage> {
    let chainValid = true;
    let events: AuditEvent[] = [];
    try {
      events = (await this.store.readAll(tenantId)).map(toEvent);
      chainValid = await this.store.verify(tenantId);
    } catch (e) {
      if (!(e instanceof LedgerChainError)) throw e;
      chainValid = false; // an altered ledger is reported, never exported as if it were sound
    }
    return { generatedAt: this.now().toISOString(), tenantId, eventCount: events.length, headHash: (await this.store.head()).hash, chainValid, events };
  }
}
