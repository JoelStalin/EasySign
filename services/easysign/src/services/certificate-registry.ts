import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Public certificate registry (Res. INDOTEL 067-2025, Annex II art. 31 and Annex I art. 36.2 m-n, 36.3).
 * Append-only, hash-chained event log: records are never deleted, so the status of a certificate stays
 * available after it expires. Revocations are published immediately and the 24 h SLA is measured.
 */

export type CertificateStatus = "active" | "suspended" | "revoked";
export type RevocationReason =
  | "unspecified" | "keyCompromise" | "caCompromise" | "affiliationChanged"
  | "superseded" | "cessationOfOperation" | "certificateHold" | "privilegeWithdrawn";

export const REVOCATION_SLA_MS = 24 * 3600_000;

export type CertificateEventType = "issued" | "suspended" | "revoked" | "reactivated";

export interface CertificateEvent {
  seq: number;
  type: CertificateEventType;
  at: string;
  serial: string;
  actor: string;
  /** issued: subject/issuer/validity; revoked: reason and request time. */
  detail: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface RegisterCertificateInput {
  serial: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  actor: string;
}

export interface PublicCertificateView {
  serial: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  /** Registry status. An expired certificate keeps its last status; `expired` is reported separately. */
  status: CertificateStatus;
  expired: boolean;
  issuedAt: string;
  statusChangedAt: string;
  revocation?: { reason: RevocationReason; requestedAt: string; publishedAt: string; withinSla: boolean };
}

export class RegistryError extends Error {
  constructor(public readonly code: "NOT_FOUND" | "ALREADY_EXISTS" | "INVALID_TRANSITION" | "INVALID_INPUT" | "CHAIN_BROKEN", message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

const GENESIS = "0".repeat(64);

const hashEvent = (e: Omit<CertificateEvent, "hash">): string =>
  createHash("sha256").update(JSON.stringify([e.seq, e.type, e.at, e.serial, e.actor, e.detail, e.prevHash])).digest("hex");

export interface CertificateRegistryOptions {
  /** JSONL file for durable storage. In-memory only when omitted. */
  filePath?: string;
  now?: () => Date;
}

export class CertificateRegistry {
  private readonly events: CertificateEvent[] = [];
  private readonly views = new Map<string, PublicCertificateView>();
  private readonly now: () => Date;
  private readonly filePath?: string;

  constructor(options: CertificateRegistryOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.filePath = options.filePath;
    if (this.filePath) {
      const dir = dirname(this.filePath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      if (existsSync(this.filePath)) this.load(readFileSync(this.filePath, "utf8"));
    }
  }

  private load(raw: string): void {
    for (const line of raw.split("\n").filter(Boolean)) {
      const e = JSON.parse(line) as CertificateEvent;
      this.assertLinks(e);
      this.apply(e);
      this.events.push(e);
    }
  }

  private assertLinks(e: CertificateEvent): void {
    const prev = this.events[this.events.length - 1];
    if (e.seq !== this.events.length + 1 || e.prevHash !== (prev?.hash ?? GENESIS) || e.hash !== hashEvent(e)) {
      throw new RegistryError("CHAIN_BROKEN", `Registry event ${e.seq} does not match the hash chain: the log was altered.`);
    }
  }

  /** Re-checks the whole chain. */
  public verifyChain(): boolean {
    let prev = GENESIS;
    return this.events.every((e, i) => {
      const ok = e.seq === i + 1 && e.prevHash === prev && e.hash === hashEvent(e);
      prev = e.hash;
      return ok;
    });
  }

  private append(type: CertificateEventType, serial: string, actor: string, detail: Record<string, unknown>): CertificateEvent {
    const prev = this.events[this.events.length - 1];
    const base = { seq: this.events.length + 1, type, at: this.now().toISOString(), serial, actor, detail, prevHash: prev?.hash ?? GENESIS };
    const e: CertificateEvent = { ...base, hash: hashEvent(base) };
    if (this.filePath) appendFileSync(this.filePath, JSON.stringify(e) + "\n");
    this.apply(e);
    this.events.push(e);
    return e;
  }

  private apply(e: CertificateEvent): void {
    if (e.type === "issued") {
      const d = e.detail as { subject: string; issuer: string; notBefore: string; notAfter: string };
      this.views.set(e.serial, { serial: e.serial, subject: d.subject, issuer: d.issuer, notBefore: d.notBefore, notAfter: d.notAfter, status: "active", expired: false, issuedAt: e.at, statusChangedAt: e.at });
      return;
    }
    const v = this.views.get(e.serial)!;
    v.statusChangedAt = e.at;
    if (e.type === "suspended") v.status = "suspended";
    if (e.type === "reactivated") v.status = "active";
    if (e.type === "revoked") {
      const d = e.detail as { reason: RevocationReason; requestedAt: string };
      v.status = "revoked";
      v.revocation = { reason: d.reason, requestedAt: d.requestedAt, publishedAt: e.at, withinSla: new Date(e.at).getTime() - new Date(d.requestedAt).getTime() <= REVOCATION_SLA_MS };
    }
  }

  private view(serial: string): PublicCertificateView {
    const v = this.views.get(serial.toUpperCase());
    if (!v) throw new RegistryError("NOT_FOUND", `Certificate ${serial} is not in the registry.`);
    return v;
  }

  public register(input: RegisterCertificateInput): PublicCertificateView {
    const serial = input.serial.trim().toUpperCase();
    if (!/^[0-9A-F]{1,64}$/.test(serial)) throw new RegistryError("INVALID_INPUT", "serial must be hexadecimal.");
    if (this.views.has(serial)) throw new RegistryError("ALREADY_EXISTS", `Certificate ${serial} is already registered.`);
    if (!(new Date(input.notBefore) < new Date(input.notAfter))) throw new RegistryError("INVALID_INPUT", "notBefore must be earlier than notAfter.");
    this.append("issued", serial, input.actor, { subject: input.subject, issuer: input.issuer, notBefore: input.notBefore, notAfter: input.notAfter });
    return this.get(serial);
  }

  public suspend(serial: string, actor: string): PublicCertificateView {
    const v = this.view(serial);
    if (v.status !== "active") throw new RegistryError("INVALID_TRANSITION", `Only an active certificate can be suspended (current: ${v.status}).`);
    this.append("suspended", v.serial, actor, { reason: "certificateHold" });
    return this.get(v.serial);
  }

  public reactivate(serial: string, actor: string): PublicCertificateView {
    const v = this.view(serial);
    if (v.status !== "suspended") throw new RegistryError("INVALID_TRANSITION", `Only a suspended certificate can be reactivated; a revoked one cannot (current: ${v.status}).`);
    this.append("reactivated", v.serial, actor, {});
    return this.get(v.serial);
  }

  /** Revocation is final. `requestedAt` is when the holder or authority asked; it starts the 24 h publication SLA. */
  public revoke(serial: string, actor: string, reason: RevocationReason = "unspecified", requestedAt?: string): PublicCertificateView {
    const v = this.view(serial);
    if (v.status === "revoked") throw new RegistryError("INVALID_TRANSITION", "Certificate is already revoked.");
    const requested = requestedAt ?? this.now().toISOString();
    if (Number.isNaN(Date.parse(requested)) || new Date(requested) > this.now()) throw new RegistryError("INVALID_INPUT", "requestedAt must be a past or present timestamp.");
    this.append("revoked", v.serial, actor, { reason, requestedAt: requested });
    return this.get(v.serial);
  }

  public get(serial: string): PublicCertificateView {
    const v = this.view(serial);
    return { ...v, expired: new Date(v.notAfter) < this.now() };
  }

  public list(filter: { status?: CertificateStatus; limit?: number; offset?: number } = {}): { total: number; items: PublicCertificateView[] } {
    const all = [...this.views.keys()].map((s) => this.get(s)).filter((v) => !filter.status || v.status === filter.status);
    const offset = Math.max(0, filter.offset ?? 0);
    return { total: all.length, items: all.slice(offset, offset + Math.min(500, filter.limit ?? 100)) };
  }

  /** JSON revocation list (not an X.509 CRL; a signed CRL needs the CA key and is tracked as pending). */
  public revocationList(): { thisUpdate: string; format: string; revoked: Array<{ serial: string; reason: RevocationReason; publishedAt: string }> } {
    return {
      thisUpdate: this.now().toISOString(),
      format: "easysign-json-v1",
      revoked: [...this.views.values()].filter((v) => v.revocation).map((v) => ({ serial: v.serial, reason: v.revocation!.reason, publishedAt: v.revocation!.publishedAt })),
    };
  }

  /** Revocations published after more than 24 h from the request (monitoring for Annex I art. 36.2 n). */
  public slaBreaches(): PublicCertificateView[] {
    return [...this.views.values()].filter((v) => v.revocation && !v.revocation.withinSla).map((v) => this.get(v.serial));
  }

  public history(serial: string): CertificateEvent[] {
    const s = this.view(serial).serial;
    return this.events.filter((e) => e.serial === s);
  }
}
