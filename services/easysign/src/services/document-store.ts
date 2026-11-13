import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DocumentKeyError, EnvelopeError, envelopeKekId, isEnvelope, loadDocumentKeyring, openDocument, rewrapDocument, sealDocument, type DocumentKeyring } from "./document-crypto.js";

/**
 * Content-addressed store for the documents people sign. The type is decided by the file's own bytes, never by the
 * client's headers, and only types a browser can show safely are accepted. Files are stored under their SHA-256, so the
 * stored bytes can always be checked against the hash that the signers confirm.
 *
 * With a keyring the files are encrypted at rest (see document-crypto.ts and docs/ENCRYPTION_AT_REST.md). The file name
 * stays the SHA-256 of the plaintext and is checked again after decrypting. Files written before encryption was turned
 * on stay readable and are encrypted by `reencryptAll`.
 */

export type DocumentType = "application/pdf" | "image/png" | "image/jpeg" | "text/plain";
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

export class DocumentError extends Error {
  constructor(public readonly code: "TOO_LARGE" | "UNSUPPORTED_TYPE" | "EMPTY" | "NOT_FOUND" | "KEY_UNAVAILABLE" | "DECRYPT_FAILED", message: string) {
    super(message);
    this.name = "DocumentError";
  }
}

export function detectType(bytes: Buffer): DocumentType | undefined {
  if (bytes.subarray(0, 5).toString("latin1") === "%PDF-") return "application/pdf";
  if (bytes.length > 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return bytes.includes(0) ? undefined : "text/plain"; // a NUL byte means binary, not text
  } catch {
    return undefined;
  }
}

export const sha256Hex = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

/** Keeps only characters that are safe in a Content-Disposition filename. */
export const safeFileName = (name: string | undefined, type: DocumentType): string => {
  const ext = { "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg", "text/plain": "txt" }[type];
  const base = (name ?? "documento").replace(/\.[A-Za-z0-9]{1,5}$/, "").replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^[._-]+/, "").slice(0, 80) || "documento";
  return `${base}.${ext}`;
};

const HASH = /^[0-9a-f]{64}$/;

export interface ReencryptReport {
  /** Unencrypted legacy files that are now encrypted. */
  encrypted: number;
  /** Files whose data key was rewrapped from a previous KEK to the current one. */
  rewrapped: number;
  /** Files already under the current KEK. */
  unchanged: number;
  /** Files left exactly as they were, with the reason. */
  failed: { hash: string; reason: string }[];
}

export class DocumentStore {
  private readonly memory = new Map<string, { bytes: Buffer; type: DocumentType }>();

  /**
   * `dir` makes the store durable (EASYSIGN_DOCS_DIR); without it documents live in memory only.
   * `keyring` encrypts what is written to `dir`; without it files are written in the clear.
   */
  constructor(private readonly dir?: string, private readonly keyring?: DocumentKeyring) {
    if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  public get encrypted(): boolean {
    return Boolean(this.keyring);
  }

  public put(bytes: Buffer): { hash: string; contentType: DocumentType; size: number } {
    if (!bytes.length) throw new DocumentError("EMPTY", "The document is empty.");
    if (bytes.length > MAX_DOCUMENT_BYTES) throw new DocumentError("TOO_LARGE", `The document exceeds ${MAX_DOCUMENT_BYTES / 1024 / 1024} MB.`);
    const contentType = detectType(bytes);
    if (!contentType) throw new DocumentError("UNSUPPORTED_TYPE", "Only PDF, PNG, JPEG or UTF-8 text documents are accepted.");
    const hash = sha256Hex(bytes);
    if (this.dir) this.write(hash, this.keyring ? sealDocument(bytes, hash, this.keyring) : bytes);
    else this.memory.set(hash, { bytes, type: contentType });
    return { hash, contentType, size: bytes.length };
  }

  public get(hash: string): { bytes: Buffer; contentType: DocumentType } {
    if (!HASH.test(hash)) throw new DocumentError("NOT_FOUND", "Document not found.");
    const mem = this.memory.get(hash);
    if (mem) return { bytes: mem.bytes, contentType: mem.type };
    if (this.dir && existsSync(join(this.dir, hash))) {
      const raw = readFileSync(join(this.dir, hash));
      if (isEnvelope(raw)) return this.open(raw, hash);
      const contentType = detectType(raw);
      // the file name is its hash: if the bytes no longer match, the store was altered
      if (contentType && sha256Hex(raw) === hash) return { bytes: raw, contentType };
    }
    throw new DocumentError("NOT_FOUND", "Document not found.");
  }

  /**
   * Brings every file under the current KEK: unencrypted legacy files are encrypted and files wrapped with a previous
   * KEK get their data key rewrapped. Each file is checked against its hash first and replaced atomically; a file that
   * fails is reported and left untouched. Safe to run again, and while the service is running.
   */
  public reencryptAll(): ReencryptReport {
    if (!this.dir) throw new DocumentKeyError("There is nothing to re-encrypt: the store has no directory (EASYSIGN_DOCS_DIR).");
    const keyring = this.keyring;
    if (!keyring) throw new DocumentKeyError("Re-encryption needs a key (EASYSIGN_DOCS_KEK and EASYSIGN_DOCS_KEK_ID).");
    const report: ReencryptReport = { encrypted: 0, rewrapped: 0, unchanged: 0, failed: [] };
    for (const hash of readdirSync(this.dir).filter((name) => HASH.test(name)).sort()) {
      try {
        const raw = readFileSync(join(this.dir, hash));
        if (!isEnvelope(raw)) {
          if (!detectType(raw) || sha256Hex(raw) !== hash) throw new DocumentError("DECRYPT_FAILED", "the unencrypted file does not match its hash");
          this.write(hash, sealDocument(raw, hash, keyring));
          report.encrypted++;
          continue;
        }
        this.open(raw, hash); // never rewrap something that does not decrypt to its hash
        if (envelopeKekId(raw) === keyring.currentId) {
          report.unchanged++;
          continue;
        }
        const rewrapped = rewrapDocument(raw, hash, keyring);
        this.open(rewrapped, hash);
        this.write(hash, rewrapped);
        report.rewrapped++;
      } catch (e) {
        report.failed.push({ hash, reason: e instanceof Error ? e.message : String(e) });
      }
    }
    return report;
  }

  private open(raw: Buffer, hash: string): { bytes: Buffer; contentType: DocumentType } {
    let bytes: Buffer;
    try {
      bytes = openDocument(raw, hash, this.keyring);
    } catch (e) {
      if (e instanceof EnvelopeError) throw new DocumentError(e.code, e.message);
      throw e;
    }
    const contentType = detectType(bytes);
    if (!contentType || sha256Hex(bytes) !== hash) throw new DocumentError("DECRYPT_FAILED", "The stored document could not be decrypted: the content does not match its hash.");
    return { bytes, contentType };
  }

  /** Writes to a temporary name and renames, so a crash never leaves a half-written document under its hash. */
  private write(hash: string, data: Buffer): void {
    const tmp = join(this.dir!, `.tmp-${hash}-${randomBytes(6).toString("hex")}`);
    writeFileSync(tmp, data, { flag: "wx", mode: 0o600 });
    renameSync(tmp, join(this.dir!, hash));
  }
}

/**
 * Builds the store from EASYSIGN_DOCS_DIR and the EASYSIGN_DOCS_KEK* variables. In production a missing key stops the
 * start-up; elsewhere the store works unencrypted and says so.
 */
export function documentStoreFromEnv(env: NodeJS.ProcessEnv = process.env, warn: (message: string) => void = (m) => console.warn(m)): DocumentStore {
  const keyring = loadDocumentKeyring(env);
  if (!keyring) {
    if (env.NODE_ENV === "production") {
      throw new DocumentKeyError("EASYSIGN_DOCS_KEK and EASYSIGN_DOCS_KEK_ID are required in production: documents must be encrypted at rest. See docs/ENCRYPTION_AT_REST.md.");
    }
    if (env.EASYSIGN_DOCS_DIR) warn("[easysign] EASYSIGN_DOCS_KEK is not set: documents in EASYSIGN_DOCS_DIR are stored WITHOUT encryption. Acceptable for development only.");
  }
  return new DocumentStore(env.EASYSIGN_DOCS_DIR, keyring);
}
