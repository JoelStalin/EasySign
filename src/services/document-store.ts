import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Content-addressed store for the documents people sign. The type is decided by the file's own bytes, never by the
 * client's headers, and only types a browser can show safely are accepted. Files are stored under their SHA-256, so the
 * stored bytes can always be checked against the hash that the signers confirm.
 */

export type DocumentType = "application/pdf" | "image/png" | "image/jpeg" | "text/plain";
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;

export class DocumentError extends Error {
  constructor(public readonly code: "TOO_LARGE" | "UNSUPPORTED_TYPE" | "EMPTY" | "NOT_FOUND", message: string) {
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

export class DocumentStore {
  private readonly memory = new Map<string, { bytes: Buffer; type: DocumentType }>();

  /** `dir` makes the store durable (EASYSIGN_DOCS_DIR); without it documents live in memory only. */
  constructor(private readonly dir?: string) {
    if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  public put(bytes: Buffer): { hash: string; contentType: DocumentType; size: number } {
    if (!bytes.length) throw new DocumentError("EMPTY", "The document is empty.");
    if (bytes.length > MAX_DOCUMENT_BYTES) throw new DocumentError("TOO_LARGE", `The document exceeds ${MAX_DOCUMENT_BYTES / 1024 / 1024} MB.`);
    const contentType = detectType(bytes);
    if (!contentType) throw new DocumentError("UNSUPPORTED_TYPE", "Only PDF, PNG, JPEG or UTF-8 text documents are accepted.");
    const hash = sha256Hex(bytes);
    if (this.dir) writeFileSync(join(this.dir, hash), bytes, { flag: "w", mode: 0o600 });
    else this.memory.set(hash, { bytes, type: contentType });
    return { hash, contentType, size: bytes.length };
  }

  public get(hash: string): { bytes: Buffer; contentType: DocumentType } {
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new DocumentError("NOT_FOUND", "Document not found.");
    const mem = this.memory.get(hash);
    if (mem) return { bytes: mem.bytes, contentType: mem.type };
    if (this.dir && existsSync(join(this.dir, hash))) {
      const bytes = readFileSync(join(this.dir, hash));
      const contentType = detectType(bytes);
      // the file name is its hash: if the bytes no longer match, the store was altered
      if (contentType && sha256Hex(bytes) === hash) return { bytes, contentType };
    }
    throw new DocumentError("NOT_FOUND", "Document not found.");
  }
}
