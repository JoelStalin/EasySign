import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Consent ledger (Ley 172-13 data protection; Res. INDOTEL 067-2025 Annex II art. 33 d-e).
 * Append-only and hash-chained. Contact for marketing is denied unless an explicit, current grant exists.
 */

export type ConsentPurpose = "signature_service_terms" | "personal_data_processing" | "identity_verification" | "marketing";

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
  evidence: { channel: string; ip?: string; userAgent?: string };
  prevHash: string;
  hash: string;
}

export class ConsentError extends Error {
  constructor(public readonly code: "INVALID_INPUT" | "NOT_GRANTED" | "CHAIN_BROKEN", message: string) {
    super(message);
    this.name = "ConsentError";
  }
}

const GENESIS = "0".repeat(64);
const hashOf = (e: Omit<ConsentEvent, "hash">) =>
  createHash("sha256").update(JSON.stringify([e.seq, e.type, e.at, e.tenantId, e.subjectId, e.purpose, e.textVersion, e.textHash, e.evidence, e.prevHash])).digest("hex");

export interface GrantInput {
  tenantId: string;
  subjectId: string;
  purpose: ConsentPurpose;
  textVersion: string;
  /** The full text shown to the subject; only its hash is stored. */
  text: string;
  evidence: { channel: string; ip?: string; userAgent?: string };
}

export class ConsentLedger {
  private readonly events: ConsentEvent[] = [];
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
          const e = JSON.parse(line) as ConsentEvent;
          const prev = this.events[this.events.length - 1];
          if (e.seq !== this.events.length + 1 || e.prevHash !== (prev?.hash ?? GENESIS) || e.hash !== hashOf(e)) {
            throw new ConsentError("CHAIN_BROKEN", `Consent event ${e.seq} does not match the hash chain.`);
          }
          this.events.push(e);
        }
      }
    }
  }

  private append(base: Omit<ConsentEvent, "seq" | "at" | "prevHash" | "hash">): ConsentEvent {
    const prev = this.events[this.events.length - 1];
    const core = { ...base, seq: this.events.length + 1, at: this.now().toISOString(), prevHash: prev?.hash ?? GENESIS };
    const e: ConsentEvent = { ...core, hash: hashOf(core) };
    if (this.filePath) appendFileSync(this.filePath, JSON.stringify(e) + "\n");
    this.events.push(e);
    return e;
  }

  public grant(input: GrantInput): ConsentEvent {
    if (!input.tenantId || !input.subjectId || !input.text.trim() || !input.textVersion) throw new ConsentError("INVALID_INPUT", "tenantId, subjectId, textVersion and the consent text are required.");
    return this.append({ type: "granted", tenantId: input.tenantId, subjectId: input.subjectId, purpose: input.purpose, textVersion: input.textVersion, textHash: createHash("sha256").update(input.text, "utf8").digest("hex"), evidence: input.evidence });
  }

  public withdraw(tenantId: string, subjectId: string, purpose: ConsentPurpose, evidence: { channel: string; ip?: string; userAgent?: string }): ConsentEvent {
    const last = this.latest(tenantId, subjectId, purpose);
    if (!last || last.type !== "granted") throw new ConsentError("NOT_GRANTED", "There is no active consent to withdraw.");
    return this.append({ type: "withdrawn", tenantId, subjectId, purpose, textVersion: last.textVersion, textHash: last.textHash, evidence });
  }

  private latest(tenantId: string, subjectId: string, purpose: ConsentPurpose): ConsentEvent | undefined {
    for (let i = this.events.length - 1; i >= 0; i--) {
      const e = this.events[i];
      if (e.tenantId === tenantId && e.subjectId === subjectId && e.purpose === purpose) return e;
    }
    return undefined;
  }

  /** True only when the latest event for that purpose is a grant. Default is false (no consent). */
  public hasConsent(tenantId: string, subjectId: string, purpose: ConsentPurpose): boolean {
    return this.latest(tenantId, subjectId, purpose)?.type === "granted";
  }

  public history(tenantId: string, subjectId: string): ConsentEvent[] {
    return this.events.filter((e) => e.tenantId === tenantId && e.subjectId === subjectId);
  }

  public verifyChain(): boolean {
    let prev = GENESIS;
    return this.events.every((e, i) => { const ok = e.seq === i + 1 && e.prevHash === prev && e.hash === hashOf(e); prev = e.hash; return ok; });
  }
}
