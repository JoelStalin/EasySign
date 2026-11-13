import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

/**
 * One-time codes for signers. A 6-digit code is sent to the signer's email; entering it proves control of that mailbox
 * at that moment. It does NOT prove civil identity (no ID document, no biometrics): that is KYC and is still pending.
 *
 * Rules: single use · expires after 10 minutes · 5 attempts per code · a new code at most every 60 s and at most
 * 5 per hour per signer · only a salted HMAC-SHA-256 of the code is kept, and only in memory (a 6-digit space is small
 * enough to brute-force offline, so the hash is never written to a ledger or a file) · constant-time comparison.
 * After a restart pending codes are gone: the signer asks for a new one.
 */

export type OtpErrorCode = "RESEND_TOO_SOON" | "RESEND_LIMIT" | "NO_CODE" | "EXPIRED" | "TOO_MANY_ATTEMPTS" | "INVALID";

export class OtpError extends Error {
  constructor(public readonly code: OtpErrorCode, message: string, public readonly meta: { retryAfterSeconds?: number; attemptsLeft?: number } = {}) {
    super(message);
    this.name = "OtpError";
  }
}

export interface OtpOptions {
  now?: () => Date;
  /** Returns the 6-digit code. Only for tests; the default uses the system CSPRNG. */
  generate?: () => string;
  ttlMs?: number;
  maxAttempts?: number;
  resendIntervalMs?: number;
  maxSendsPerWindow?: number;
  sendWindowMs?: number;
}

interface Entry {
  /** Undefined once the code was used, expired or revoked. */
  code?: { salt: Buffer; hash: Buffer; expiresAt: number; attempts: number };
  /** Times (ms) at which codes were issued, for the resend limits. */
  sends: number[];
}

const digest = (salt: Buffer, code: string) => createHmac("sha256", salt).update(code, "utf8").digest();

export class SignerOtpService {
  private readonly entries = new Map<string, Entry>();
  private readonly now: () => Date;
  private readonly generate: () => string;
  public readonly ttlMs: number;
  public readonly maxAttempts: number;
  private readonly resendIntervalMs: number;
  private readonly maxSendsPerWindow: number;
  private readonly sendWindowMs: number;

  constructor(options: OtpOptions = {}) {
    this.now = options.now ?? (() => new Date());
    this.generate = options.generate ?? (() => String(randomInt(0, 1_000_000)).padStart(6, "0"));
    this.ttlMs = options.ttlMs ?? 10 * 60_000;
    this.maxAttempts = options.maxAttempts ?? 5;
    this.resendIntervalMs = options.resendIntervalMs ?? 60_000;
    this.maxSendsPerWindow = options.maxSendsPerWindow ?? 5;
    this.sendWindowMs = options.sendWindowMs ?? 60 * 60_000;
  }

  /** Issues a new code for `key`, replacing any previous one. The clear code is returned once, to be sent, and is not kept. */
  public issue(key: string): { code: string; expiresAt: Date } {
    const t = this.now().getTime();
    this.sweep(t);
    const entry = this.entries.get(key) ?? { sends: [] };
    entry.sends = entry.sends.filter((at) => t - at < this.sendWindowMs);
    const lastSend = entry.sends[entry.sends.length - 1];
    if (lastSend !== undefined && t - lastSend < this.resendIntervalMs) {
      const retryAfterSeconds = Math.ceil((this.resendIntervalMs - (t - lastSend)) / 1000);
      throw new OtpError("RESEND_TOO_SOON", `Wait ${retryAfterSeconds} s before asking for another code.`, { retryAfterSeconds });
    }
    if (entry.sends.length >= this.maxSendsPerWindow) {
      const retryAfterSeconds = Math.ceil((this.sendWindowMs - (t - entry.sends[0])) / 1000);
      throw new OtpError("RESEND_LIMIT", "Too many codes were requested for this signer.", { retryAfterSeconds });
    }
    const code = this.generate();
    if (!/^\d{6}$/.test(code)) throw new Error("The code generator must return 6 digits.");
    const salt = randomBytes(16);
    entry.code = { salt, hash: digest(salt, code), expiresAt: t + this.ttlMs, attempts: 0 };
    entry.sends.push(t);
    this.entries.set(key, entry);
    return { code, expiresAt: new Date(t + this.ttlMs) };
  }

  /** Checks a code. On success the code is consumed. Every wrong try counts, and the fifth one kills the code. */
  public verify(key: string, candidate: string): void {
    const t = this.now().getTime();
    const entry = this.entries.get(key);
    const current = entry?.code;
    if (!entry || !current) throw new OtpError("NO_CODE", "There is no active code: ask for a new one.");
    if (t >= current.expiresAt) {
      entry.code = undefined;
      throw new OtpError("EXPIRED", "The code has expired: ask for a new one.");
    }
    if (current.attempts >= this.maxAttempts) throw new OtpError("TOO_MANY_ATTEMPTS", "Too many wrong attempts: ask for a new code.", { attemptsLeft: 0 });
    current.attempts += 1;
    const given = digest(current.salt, String(candidate)); // same length as the stored hash whatever the input
    if (!timingSafeEqual(given, current.hash)) {
      throw new OtpError("INVALID", "The code is not correct.", { attemptsLeft: this.maxAttempts - current.attempts });
    }
    entry.code = undefined; // single use
  }

  /** Drops the active code (e.g. the email could not be sent). The send still counts for the resend limits. */
  public revoke(key: string): void {
    const entry = this.entries.get(key);
    if (entry) entry.code = undefined;
  }

  private sweep(t: number): void {
    if (this.entries.size < 5000) return;
    for (const [key, e] of this.entries) {
      const live = e.code && t < e.code.expiresAt;
      if (!live && e.sends.every((at) => t - at >= this.sendWindowMs)) this.entries.delete(key);
    }
  }
}
