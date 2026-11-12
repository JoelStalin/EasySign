import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { NON_QUALIFIED_NOTICE } from "./legal-notices.js";
import { CHANNELS, type DeliveryChannel } from "./delivery.js";

/**
 * Signature request workflow (backlog ES-009) for a NON-QUALIFIED electronic signature provider (Route A).
 * Sequential or parallel signers, one-time tokens (only their SHA-256 is stored), explicit consent before signing,
 * document hash confirmation, expiry, and an append-only hash-chained event log that backs the evidence package.
 * The result is an electronic signature without the legal value of firma digital (Res. INDOTEL 067-2025, Annex II art. 29.1).
 */

export type RequestStatus = "draft" | "pending" | "completed" | "cancelled" | "expired";
export type SignerStatus = "waiting" | "notified" | "viewed" | "consented" | "signed" | "declined";
type EventType = "created" | "document_attached" | "document_viewed" | "reissued" | "sent" | "viewed" | "consented" | "signed" | "declined" | "cancelled" | "expired" | "completed";

export interface WorkflowEvent {
  seq: number;
  type: EventType;
  at: string;
  requestId: string;
  signerId?: string;
  detail: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface Signer {
  id: string;
  name: string;
  email: string;
  order: number;
  channel: DeliveryChannel;
  phone?: string;
  status: SignerStatus;
  consentedAt?: string;
  documentViewedAt?: string;
  signedAt?: string;
  declinedReason?: string;
}

export interface SignatureRequest {
  id: string;
  tenantId: string;
  documentName: string;
  /** SHA-256 (hex) of the document being signed; the document itself is not stored here. */
  documentHash: string;
  ordering: "sequential" | "parallel";
  status: RequestStatus;
  createdAt: string;
  expiresAt: string;
  completedAt?: string;
  cancelReason?: string;
  /** The document the signers must open before accepting and signing (stored in the document store under documentHash). */
  document?: { contentType: string; size: number; fileName: string };
  signers: Signer[];
}

export class WorkflowError extends Error {
  constructor(
    public readonly code: "NOT_FOUND" | "INVALID_INPUT" | "INVALID_STATE" | "UNAUTHORIZED" | "LOCKED" | "EXPIRED" | "NOT_YOUR_TURN" | "DOCUMENT_MISMATCH" | "CHAIN_BROKEN",
    message: string
  ) {
    super(message);
    this.name = "WorkflowError";
  }
}

export interface CreateInput {
  tenantId: string;
  documentName: string;
  documentHash: string;
  ordering?: "sequential" | "parallel";
  expiresInHours?: number;
  signers: Array<{ name: string; email: string; channel?: DeliveryChannel; phone?: string }>;
}

export interface IssuedToken { signerId: string; name: string; email: string; phone?: string; order: number; token: string; channel: DeliveryChannel }

const GENESIS = "0".repeat(64);
const MAX_ATTEMPTS = 5;
const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const hashEvent = (e: Omit<WorkflowEvent, "hash">) => sha256(JSON.stringify([e.seq, e.type, e.at, e.requestId, e.signerId ?? null, e.detail, e.prevHash]));
const newToken = () => randomBytes(32).toString("base64url");

export class SignatureWorkflow {
  private readonly events: WorkflowEvent[] = [];
  private readonly requests = new Map<string, SignatureRequest>();
  private readonly tokenHashes = new Map<string, string>(); // `${requestId}:${signerId}` -> sha256(token)
  private readonly failures = new Map<string, number>();
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
          const e = JSON.parse(line) as WorkflowEvent;
          const prev = this.events[this.events.length - 1];
          if (e.seq !== this.events.length + 1 || e.prevHash !== (prev?.hash ?? GENESIS) || e.hash !== hashEvent(e)) {
            throw new WorkflowError("CHAIN_BROKEN", `Workflow event ${e.seq} does not match the hash chain.`);
          }
          this.apply(e);
          this.events.push(e);
        }
      }
    }
  }

  // ---- event log ----
  private append(type: EventType, requestId: string, detail: Record<string, unknown>, signerId?: string): WorkflowEvent {
    const prev = this.events[this.events.length - 1];
    const core = { seq: this.events.length + 1, type, at: this.now().toISOString(), requestId, signerId, detail, prevHash: prev?.hash ?? GENESIS };
    const e: WorkflowEvent = { ...core, hash: hashEvent(core) };
    if (this.filePath) appendFileSync(this.filePath, JSON.stringify(e) + "\n");
    this.apply(e);
    this.events.push(e);
    return e;
  }

  private apply(e: WorkflowEvent): void {
    if (e.type === "created") {
      const d = e.detail as { tenantId: string; documentName: string; documentHash: string; ordering: "sequential" | "parallel"; expiresAt: string; signers: Array<Omit<Signer, "status">> };
      this.requests.set(e.requestId, { id: e.requestId, tenantId: d.tenantId, documentName: d.documentName, documentHash: d.documentHash, ordering: d.ordering, status: "draft", createdAt: e.at, expiresAt: d.expiresAt, signers: d.signers.map((s) => ({ ...s, status: "waiting" as SignerStatus })) });
      return;
    }
    const r = this.requests.get(e.requestId)!;
    const s = e.signerId ? r.signers.find((x) => x.id === e.signerId) : undefined;
    const issue = (tokens: Record<string, string> | undefined) => {
      for (const [signerId, h] of Object.entries(tokens ?? {})) {
        this.tokenHashes.set(`${r.id}:${signerId}`, h);
        const t = r.signers.find((x) => x.id === signerId);
        if (t && t.status === "waiting") t.status = "notified";
      }
    };
    switch (e.type) {
      case "sent": r.status = "pending"; issue(e.detail.tokenHashes as Record<string, string>); break;
      case "document_attached": r.document = { contentType: String(e.detail.contentType), size: Number(e.detail.size), fileName: String(e.detail.fileName) }; break;
      case "document_viewed": if (s && !s.documentViewedAt) s.documentViewedAt = e.at; break;
      case "reissued": issue(e.detail.tokenHashes as Record<string, string>); break;
      case "viewed": if (s && s.status === "notified") s.status = "viewed"; break;
      case "consented": if (s) { s.status = "consented"; s.consentedAt = e.at; } break;
      case "signed": if (s) { s.status = "signed"; s.signedAt = e.at; } issue(e.detail.nextTokenHashes as Record<string, string>); break;
      case "declined": if (s) { s.status = "declined"; s.declinedReason = String(e.detail.reason ?? ""); } r.status = "cancelled"; r.cancelReason = "declined by a signer"; break;
      case "cancelled": r.status = "cancelled"; r.cancelReason = String(e.detail.reason ?? ""); break;
      case "expired": r.status = "expired"; break;
      case "completed": r.status = "completed"; r.completedAt = e.at; break;
    }
  }

  public verifyChain(): boolean {
    let prev = GENESIS;
    return this.events.every((e, i) => { const ok = e.seq === i + 1 && e.prevHash === prev && e.hash === hashEvent(e); prev = e.hash; return ok; });
  }

  // ---- helpers ----
  private req(id: string): SignatureRequest {
    const r = this.requests.get(id);
    if (!r) throw new WorkflowError("NOT_FOUND", `Signature request ${id} does not exist.`);
    return r;
  }

  private expireIfDue(r: SignatureRequest): void {
    if ((r.status === "pending" || r.status === "draft") && new Date(r.expiresAt) <= this.now()) this.append("expired", r.id, {});
  }

  /** Verifies the signer's one-time token. Five failures lock the signer until an administrator re-sends. */
  private authenticate(requestId: string, signerId: string, token: string): { r: SignatureRequest; s: Signer } {
    const r = this.req(requestId);
    this.expireIfDue(r);
    if (r.status === "expired") throw new WorkflowError("EXPIRED", "This signature request has expired.");
    if (r.status !== "pending") throw new WorkflowError("INVALID_STATE", `The request is ${r.status}.`);
    const s = r.signers.find((x) => x.id === signerId);
    const key = `${requestId}:${signerId}`;
    const stored = this.tokenHashes.get(key);
    if (!s || !stored) throw new WorkflowError("UNAUTHORIZED", "Invalid signer or token.");
    if ((this.failures.get(key) ?? 0) >= MAX_ATTEMPTS) throw new WorkflowError("LOCKED", "Too many failed attempts for this signer.");
    const a = Buffer.from(sha256(token)), b = Buffer.from(stored);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      this.failures.set(key, (this.failures.get(key) ?? 0) + 1);
      throw new WorkflowError("UNAUTHORIZED", "Invalid signer or token.");
    }
    this.failures.delete(key);
    if (s.status === "waiting") throw new WorkflowError("NOT_YOUR_TURN", "It is not this signer's turn yet.");
    return { r, s };
  }

  private issueFor(r: SignatureRequest, targets: Signer[]): { tokens: IssuedToken[]; hashes: Record<string, string> } {
    const tokens: IssuedToken[] = [];
    const hashes: Record<string, string> = {};
    for (const s of targets) {
      const token = newToken();
      hashes[s.id] = sha256(token);
      tokens.push({ signerId: s.id, name: s.name, email: s.email, phone: s.phone, order: s.order, token, channel: s.channel });
    }
    return { tokens, hashes };
  }

  // ---- operations ----
  public create(input: CreateInput, actor: string): SignatureRequest {
    if (!input.tenantId || !input.documentName?.trim()) throw new WorkflowError("INVALID_INPUT", "tenantId and documentName are required.");
    if (!/^[0-9a-f]{64}$/.test(input.documentHash ?? "")) throw new WorkflowError("INVALID_INPUT", "documentHash must be a SHA-256 in lowercase hex.");
    if (!input.signers?.length || input.signers.length > 20) throw new WorkflowError("INVALID_INPUT", "Between 1 and 20 signers are required.");
    const emails = input.signers.map((s) => String(s.email).trim().toLowerCase());
    if (emails.some((m) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(m))) throw new WorkflowError("INVALID_INPUT", "Every signer needs a valid email.");
    if (new Set(emails).size !== emails.length) throw new WorkflowError("INVALID_INPUT", "Signer emails must be unique.");
    const hours = input.expiresInHours ?? 168;
    if (!(hours >= 1 && hours <= 720)) throw new WorkflowError("INVALID_INPUT", "expiresInHours must be between 1 and 720.");

    const id = randomUUID();
    for (const s of input.signers) {
      const ch = s.channel ?? "link";
      if (!CHANNELS.includes(ch)) throw new WorkflowError("INVALID_INPUT", `channel must be one of ${CHANNELS.join(", ")}.`);
      if (ch === "whatsapp" && !/^\+[1-9]\d{7,14}$/.test(s.phone ?? "")) throw new WorkflowError("INVALID_INPUT", "A WhatsApp signer needs a phone in international format, e.g. +18095550100.");
    }
    const signers = input.signers.map((s, i) => ({ id: randomUUID(), name: s.name.trim(), email: emails[i], order: i + 1, channel: (s.channel ?? "link") as DeliveryChannel, phone: s.phone?.trim() || undefined }));
    this.append("created", id, {
      tenantId: input.tenantId, documentName: input.documentName.trim(), documentHash: input.documentHash, ordering: input.ordering ?? "sequential",
      expiresAt: new Date(this.now().getTime() + hours * 3600_000).toISOString(), signers, createdBy: actor,
    });
    return this.get(id);
  }

  /** Moves the request to pending and returns the one-time tokens for the signers whose turn it is. Tokens are never stored in clear. */
  public send(requestId: string): { request: SignatureRequest; tokens: IssuedToken[] } {
    const r = this.req(requestId);
    if (r.status !== "draft") throw new WorkflowError("INVALID_STATE", `Only a draft can be sent (current: ${r.status}).`);
    const eligible = r.ordering === "parallel" ? r.signers : [r.signers[0]];
    const { tokens, hashes } = this.issueFor(r, eligible);
    this.append("sent", requestId, { tokenHashes: hashes, ordering: r.ordering });
    return { request: this.get(requestId), tokens };
  }

  public view(requestId: string, signerId: string, token: string): SignatureRequest {
    const { s } = this.authenticate(requestId, signerId, token);
    if (s.status === "notified") this.append("viewed", requestId, {}, signerId);
    return this.get(requestId);
  }

  /** The signer accepts the exact disclosure shown (its hash is recorded). Required before signing. */
  public consent(requestId: string, signerId: string, token: string, disclosureHash: string, expectedDisclosureHash: string, evidence: { ip?: string; userAgent?: string }): SignatureRequest {
    const { s } = this.authenticate(requestId, signerId, token);
    if (s.status !== "viewed") throw new WorkflowError("INVALID_STATE", `The signer must view the document first (status: ${s.status}).`);
    if (this.requests.get(requestId)!.document && !s.documentViewedAt) throw new WorkflowError("INVALID_STATE", "The signer must open the document before accepting the terms.");
    if (disclosureHash !== expectedDisclosureHash) throw new WorkflowError("INVALID_INPUT", "The accepted disclosure is not the current one.");
    this.append("consented", requestId, { disclosureHash, ...evidence }, signerId);
    return this.get(requestId);
  }

  public sign(requestId: string, signerId: string, token: string, documentHash: string, evidence: { ip?: string; userAgent?: string }): { request: SignatureRequest; next: IssuedToken[] } {
    const { r, s } = this.authenticate(requestId, signerId, token);
    if (s.status !== "consented") throw new WorkflowError("INVALID_STATE", "The signer must accept the service terms before signing.");
    if (r.document && !s.documentViewedAt) throw new WorkflowError("INVALID_STATE", "The signer must open the document before signing.");
    if (documentHash !== r.documentHash) throw new WorkflowError("DOCUMENT_MISMATCH", "The confirmed document hash does not match the document of this request.");
    if (r.ordering === "sequential" && r.signers.some((x) => x.order < s.order && x.status !== "signed")) throw new WorkflowError("NOT_YOUR_TURN", "Previous signers have not signed yet.");

    const upcoming = r.ordering === "sequential" ? r.signers.filter((x) => x.order === s.order + 1) : [];
    const { tokens, hashes } = this.issueFor(r, upcoming);
    this.append("signed", requestId, { documentHash, nextTokenHashes: hashes, ...evidence }, signerId);
    if (this.requests.get(requestId)!.signers.every((x) => x.status === "signed")) this.append("completed", requestId, { documentHash });
    return { request: this.get(requestId), next: tokens };
  }

  public decline(requestId: string, signerId: string, token: string, reason: string): SignatureRequest {
    this.authenticate(requestId, signerId, token);
    this.append("declined", requestId, { reason: reason.slice(0, 300) }, signerId);
    return this.get(requestId);
  }

  public cancel(requestId: string, reason: string): SignatureRequest {
    const r = this.req(requestId);
    if (r.status !== "draft" && r.status !== "pending") throw new WorkflowError("INVALID_STATE", `A ${r.status} request cannot be cancelled.`);
    this.append("cancelled", requestId, { reason: reason.slice(0, 300) });
    return this.get(requestId);
  }

  /**
   * New one-time token for a signer whose turn has come (lost link, lockout, or a restart that dropped pending tokens).
   * The previous token stops working. The client may switch channel (e.g. from email to an on-screen QR).
   */
  public reissue(requestId: string, signerId: string, channel?: DeliveryChannel): IssuedToken {
    const r = this.req(requestId);
    this.expireIfDue(r);
    if (r.status !== "pending") throw new WorkflowError(r.status === "expired" ? "EXPIRED" : "INVALID_STATE", `The request is ${r.status}.`);
    const s = r.signers.find((x) => x.id === signerId);
    if (!s) throw new WorkflowError("NOT_FOUND", "Signer not found in this request.");
    if (!(["notified", "viewed", "consented"] as SignerStatus[]).includes(s.status)) throw new WorkflowError("INVALID_STATE", `A signer in status ${s.status} cannot be re-issued.`);
    if (channel && !CHANNELS.includes(channel)) throw new WorkflowError("INVALID_INPUT", "Unknown channel.");
    if (channel === "whatsapp" && !s.phone) throw new WorkflowError("INVALID_INPUT", "This signer has no phone for WhatsApp.");
    const { tokens, hashes } = this.issueFor(r, [channel ? { ...s, channel } : s]);
    this.append("reissued", requestId, { tokenHashes: hashes, channel: tokens[0].channel }, signerId);
    this.failures.delete(`${requestId}:${signerId}`);
    return tokens[0];
  }

  /** Registers that the document bytes were stored for this request (draft only). The bytes' hash is checked by the caller. */
  public attachDocument(requestId: string, meta: { contentType: string; size: number; fileName: string }): SignatureRequest {
    const r = this.req(requestId);
    if (r.status !== "draft") throw new WorkflowError("INVALID_STATE", `A document can only be attached to a draft (current: ${r.status}).`);
    this.append("document_attached", requestId, { ...meta });
    return this.get(requestId);
  }

  /** Authenticates the signer and records, once, that they opened the document. Returns the document metadata. */
  public documentAccess(requestId: string, signerId: string, token: string): { contentType: string; size: number; fileName: string } {
    const { r, s } = this.authenticate(requestId, signerId, token);
    if (!r.document) throw new WorkflowError("INVALID_STATE", "This request has no document on the platform.");
    if (!s.documentViewedAt) this.append("document_viewed", requestId, {}, signerId);
    return r.document;
  }

  public get(requestId: string): SignatureRequest {
    const r = this.req(requestId);
    this.expireIfDue(r);
    return structuredClone(this.requests.get(requestId)!);
  }

  /** Evidence package: what happened, in order, anchored by hash. It is electronic-signature evidence, not firma digital. */
  public evidence(requestId: string) {
    const request = this.get(requestId);
    const events = this.events.filter((e) => e.requestId === requestId);
    const body = {
      notice: NON_QUALIFIED_NOTICE,
      request,
      events: events.map((e) => ({ seq: e.seq, type: e.type, at: e.at, signerId: e.signerId, hash: e.hash })),
      ledgerHeadHash: this.events[this.events.length - 1]?.hash ?? GENESIS,
      chainValid: this.verifyChain(),
    };
    return { ...body, packageHash: sha256(JSON.stringify(body)) };
  }
}
