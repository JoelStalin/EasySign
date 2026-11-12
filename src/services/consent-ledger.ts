import { createHash } from "node:crypto";
import { FileLedgerStore, LedgerChainError, type LedgerDefinition, type LedgerRecord, type LedgerStore } from "../storage/ledger-store.js";

/**
 * Consent ledger (Ley 172-13 data protection; Res. INDOTEL 067-2025 Annex II art. 33 d-e).
 * Append-only and hash-chained. Contact for marketing is denied unless an explicit, current grant exists.
 * Events are kept in a LedgerStore: memory or a JSONL file by default, PostgreSQL with per-tenant row level
 * security when one is given (docs/POSTGRES_TENANCY.md). Every read is scoped to one tenant.
 */

export type ConsentPurpose = "signature_service_terms" | "personal_data_processing" | "identity_verification" | "marketing";
export interface ConsentEvidence { channel: string; ip?: string; userAgent?: string }

export interface ConsentEvent {
  seq: number;
  type: "granted" | "withdrawn";
  at: string;
  tenantId: string;
  subjectId: string;
  purpose: ConsentPurpose;
  /** Version and SHA-256 of the exact text the subject accepted. */
  textVersion: string;
  textHash: string;
  evidence: ConsentEvidence;
  prevHash: string;
  hash: string;
}

/** What a consent event stores besides the ledger envelope (seq, type, at, tenantId, hashes). */
export type ConsentPayload = Pick<ConsentEvent, "subjectId" | "purpose" | "textVersion" | "textHash" | "evidence">;

export class ConsentError extends Error {
  constructor(public readonly code: "INVALID_INPUT" | "NOT_GRANTED" | "CHAIN_BROKEN", message: string) {
    super(message);
    this.name = "ConsentError";
  }
}

/** Fixed key order, so the hash does not depend on how the caller (or jsonb) ordered the keys. */
const canonicalEvidence = (e: ConsentEvidence): ConsentEvidence => ({ channel: e.channel, ...(e.ip !== undefined ? { ip: e.ip } : {}), ...(e.userAgent !== undefined ? { userAgent: e.userAgent } : {}) });

export const CONSENT_LEDGER: LedgerDefinition<ConsentPayload> = {
  name: "consent",
  hash: (r) => createHash("sha256").update(JSON.stringify([r.seq, r.type, r.at, r.tenantId, r.payload.subjectId, r.payload.purpose, r.payload.textVersion, r.payload.textHash, r.payload.evidence, r.prevHash])).digest("hex"),
  canonical: (p) => {
    const x = p as unknown as ConsentPayload;
    return { subjectId: x.subjectId, purpose: x.purpose, textVersion: x.textVersion, textHash: x.textHash, evidence: canonicalEvidence(x.evidence) };
  },
};

const toEvent = (r: LedgerRecord<ConsentPayload>): ConsentEvent => ({
  seq: r.seq, type: r.type as ConsentEvent["type"], at: r.at, tenantId: r.tenantId,
  subjectId: r.payload.subjectId, purpose: r.payload.purpose, textVersion: r.payload.textVersion, textHash: r.payload.textHash, evidence: r.payload.evidence,
  prevHash: r.prevHash, hash: r.hash,
});

const chainBroken = (e: unknown): never => {
  if (e instanceof LedgerChainError) throw new ConsentError("CHAIN_BROKEN", `Consent event ${e.seq} does not match the hash chain.`);
  throw e;
};

export interface GrantInput {
  tenantId: string;
  subjectId: string;
  purpose: ConsentPurpose;
  textVersion: string;
  /** The full text shown to the subject; only its hash is stored. */
  text: string;
  evidence: ConsentEvidence;
}

export class ConsentLedger {
  private readonly store: LedgerStore<ConsentPayload>;
  private readonly now: () => Date;

  /** With `store` the ledger uses it; otherwise a JSONL file (`filePath`) or memory. A tampered file throws here. */
  constructor(options: { filePath?: string; store?: LedgerStore<ConsentPayload>; now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
    try {
      this.store = options.store ?? new FileLedgerStore(CONSENT_LEDGER, { filePath: options.filePath });
    } catch (e) {
      throw chainBroken(e);
    }
  }

  private async append(type: ConsentEvent["type"], tenantId: string, payload: ConsentPayload): Promise<ConsentEvent> {
    return toEvent(await this.store.append(tenantId, { type, at: this.now().toISOString(), payload }));
  }

  private async events(tenantId: string): Promise<ConsentEvent[]> {
    try {
      return (await this.store.readAll(tenantId)).map(toEvent);
    } catch (e) {
      throw chainBroken(e);
    }
  }

  private async latest(tenantId: string, subjectId: string, purpose: ConsentPurpose): Promise<ConsentEvent | undefined> {
    const events = await this.events(tenantId);
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].subjectId === subjectId && events[i].purpose === purpose) return events[i];
    }
    return undefined;
  }

  public async grant(input: GrantInput): Promise<ConsentEvent> {
    if (!input.tenantId || !input.subjectId || !input.text.trim() || !input.textVersion) throw new ConsentError("INVALID_INPUT", "tenantId, subjectId, textVersion and the consent text are required.");
    return this.append("granted", input.tenantId, { subjectId: input.subjectId, purpose: input.purpose, textVersion: input.textVersion, textHash: createHash("sha256").update(input.text, "utf8").digest("hex"), evidence: canonicalEvidence(input.evidence) });
  }

  public async withdraw(tenantId: string, subjectId: string, purpose: ConsentPurpose, evidence: ConsentEvidence): Promise<ConsentEvent> {
    const last = await this.latest(tenantId, subjectId, purpose);
    if (!last || last.type !== "granted") throw new ConsentError("NOT_GRANTED", "There is no active consent to withdraw.");
    return this.append("withdrawn", tenantId, { subjectId, purpose, textVersion: last.textVersion, textHash: last.textHash, evidence: canonicalEvidence(evidence) });
  }

  /** True only when the latest event for that purpose is a grant. Default is false (no consent). */
  public async hasConsent(tenantId: string, subjectId: string, purpose: ConsentPurpose): Promise<boolean> {
    return (await this.latest(tenantId, subjectId, purpose))?.type === "granted";
  }

  public async history(tenantId: string, subjectId: string): Promise<ConsentEvent[]> {
    return (await this.events(tenantId)).filter((e) => e.subjectId === subjectId);
  }

  /**
   * File or memory: verifies the whole chain. PostgreSQL: needs the tenant and verifies what that tenant can see;
   * the whole chain is verified with the auditor role (`npm run ledger:verify`).
   */
  public verifyChain(tenantId?: string): Promise<boolean> {
    return this.store.verify(tenantId);
  }
}
