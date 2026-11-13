import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Audit and evidence ledger (Res. INDOTEL 067-2025 Annex I art. 36.2 j: keep relevant records as legal evidence;
 * backlog ES-007). Append-only, SHA-256 hash-chained, with correlation IDs. Secrets are redacted before storage.
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

export class AuditError extends Error {
  constructor(public readonly code: "CHAIN_BROKEN" | "INVALID_INPUT", message: string) {
    super(message);
    this.name = "AuditError";
  }
}

const GENESIS = "0".repeat(64);
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

const hashOf = (e: Omit<AuditEvent, "hash">) =>
  createHash("sha256").update(JSON.stringify([e.seq, e.at, e.correlationId, e.tenantId, e.actor, e.action, e.resource, e.outcome, e.details, e.prevHash])).digest("hex");

export interface EvidencePackage {
  generatedAt: string;
  tenantId: string;
  eventCount: number;
  /** Hash of the last event of the whole ledger at export time, to anchor the package. */
  headHash: string;
  chainValid: boolean;
  events: AuditEvent[];
}

export class AuditLog {
  private readonly events: AuditEvent[] = [];
  private readonly now: () => Date;
  private readonly filePath?: string;

  constructor(options: { filePath?: string; now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
    this.filePath = options.filePath;
    if (this.filePath) {
      const dir = dirname(this.filePath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (existsSync(this.filePath)) {
        for (const line of readFileSync(this.filePath, "utf8").split("\n").filter(Boolean)) {
          const e = JSON.parse(line) as AuditEvent;
          const prev = this.events[this.events.length - 1];
          if (e.seq !== this.events.length + 1 || e.prevHash !== (prev?.hash ?? GENESIS) || e.hash !== hashOf(e)) {
            throw new AuditError("CHAIN_BROKEN", `Audit event ${e.seq} does not match the hash chain: the ledger was altered.`);
          }
          this.events.push(e);
        }
      }
    }
  }

  public record(input: AuditInput): AuditEvent {
    if (!input.correlationId || !input.tenantId || !input.actor || !input.action) throw new AuditError("INVALID_INPUT", "correlationId, tenantId, actor and action are required.");
    const prev = this.events[this.events.length - 1];
    const core = { ...input, details: redact(input.details ?? {}) as Record<string, unknown>, seq: this.events.length + 1, at: this.now().toISOString(), prevHash: prev?.hash ?? GENESIS };
    const e: AuditEvent = { ...core, hash: hashOf(core) };
    if (this.filePath) appendFileSync(this.filePath, JSON.stringify(e) + "\n");
    this.events.push(e);
    return e;
  }

  public query(filter: { tenantId?: string; action?: string; correlationId?: string; from?: string; to?: string; limit?: number } = {}): AuditEvent[] {
    return this.events
      .filter((e) => (!filter.tenantId || e.tenantId === filter.tenantId) && (!filter.action || e.action === filter.action) && (!filter.correlationId || e.correlationId === filter.correlationId)
        && (!filter.from || e.at >= filter.from) && (!filter.to || e.at <= filter.to))
      .slice(-Math.min(1000, filter.limit ?? 200));
  }

  public verifyChain(): boolean {
    let prev = GENESIS;
    return this.events.every((e, i) => { const ok = e.seq === i + 1 && e.prevHash === prev && e.hash === hashOf(e); prev = e.hash; return ok; });
  }

  public exportEvidence(tenantId: string): EvidencePackage {
    const events = this.events.filter((e) => e.tenantId === tenantId);
    return { generatedAt: this.now().toISOString(), tenantId, eventCount: events.length, headHash: this.events[this.events.length - 1]?.hash ?? GENESIS, chainValid: this.verifyChain(), events };
  }
}
