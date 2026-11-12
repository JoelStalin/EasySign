import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Envelope encryption for documents at rest. Every document gets its own random data key (DEK, AES-256-GCM); the DEK is
 * wrapped with a key-encryption key (KEK, AES-256-GCM) that comes from the environment and is never written to disk.
 * Rotating the KEK only rewraps the DEK, so the document body is not rewritten.
 *
 * File layout, version 1 (all lengths in bytes):
 *   magic "ESDOC\0" (6) | version (1) | kekIdLength (1) | kekId (1..64, ASCII)
 *   | wrapIv (12) | wrapTag (16) | wrappedDek (32) | iv (12) | tag (16) | ciphertext (rest)
 *
 * The SHA-256 of the plaintext (the file name) is authenticated data in both layers, so an envelope moved under another
 * name does not open. The magic holds a NUL byte, which no accepted plaintext type can start with, so an unencrypted
 * legacy file is never mistaken for an envelope.
 */

export const ENVELOPE_VERSION = 1;
const MAGIC = Buffer.from("ESDOC\0", "latin1");
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEK_ID = /^[A-Za-z0-9._-]{1,64}$/;
const BASE64_32_BYTES = /^[A-Za-z0-9+/]{43}=$/;

export class DocumentKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DocumentKeyError";
  }
}

export class EnvelopeError extends Error {
  constructor(public readonly code: "KEY_UNAVAILABLE" | "DECRYPT_FAILED", message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

export interface DocumentKeyring {
  /** Id of the KEK that wraps new documents. */
  readonly currentId: string;
  /** Every KEK that may unwrap a document: the current one plus the previous ones. */
  readonly keys: ReadonlyMap<string, Buffer>;
}

const decodeKek = (value: string, label: string): Buffer => {
  if (!BASE64_32_BYTES.test(value)) throw new DocumentKeyError(`${label} must be exactly 32 bytes in standard base64 (44 characters).`);
  return Buffer.from(value, "base64");
};

const checkId = (id: string, label: string): string => {
  if (!KEK_ID.test(id)) throw new DocumentKeyError(`${label} must be 1 to 64 characters from A-Z, a-z, 0-9, dot, underscore or hyphen.`);
  return id;
};

export function createKeyring(current: { id: string; key: Buffer }, previous: { id: string; key: Buffer }[] = []): DocumentKeyring {
  const keys = new Map<string, Buffer>();
  for (const { id, key } of [current, ...previous]) {
    checkId(id, "A KEK id");
    if (key.length !== KEY_BYTES) throw new DocumentKeyError(`KEK "${id}" must be exactly 32 bytes.`);
    if (keys.has(id)) throw new DocumentKeyError(`KEK id "${id}" is repeated; every key needs its own id.`);
    keys.set(id, key);
  }
  return { currentId: current.id, keys };
}

/**
 * Reads EASYSIGN_DOCS_KEK (32 bytes, base64), EASYSIGN_DOCS_KEK_ID and the optional EASYSIGN_DOCS_KEK_PREVIOUS
 * ("id:base64,id:base64"). Returns undefined when no KEK is configured. Error messages never include key material.
 */
export function loadDocumentKeyring(env: NodeJS.ProcessEnv = process.env): DocumentKeyring | undefined {
  const kek = env.EASYSIGN_DOCS_KEK?.trim();
  const previousRaw = env.EASYSIGN_DOCS_KEK_PREVIOUS?.trim();
  if (!kek) {
    if (previousRaw) throw new DocumentKeyError("EASYSIGN_DOCS_KEK_PREVIOUS is set but EASYSIGN_DOCS_KEK is empty.");
    return undefined;
  }
  const id = env.EASYSIGN_DOCS_KEK_ID?.trim();
  if (!id) throw new DocumentKeyError("EASYSIGN_DOCS_KEK is set but EASYSIGN_DOCS_KEK_ID is empty; the key id is needed to rotate keys.");
  const previous = (previousRaw ? previousRaw.split(",") : []).map((entry, i) => {
    const at = entry.indexOf(":");
    const label = `EASYSIGN_DOCS_KEK_PREVIOUS entry ${i + 1}`;
    if (at < 1) throw new DocumentKeyError(`${label} must look like "id:base64key".`);
    return { id: checkId(entry.slice(0, at).trim(), `${label} id`), key: decodeKek(entry.slice(at + 1).trim(), `${label} key`) };
  });
  return createKeyring({ id: checkId(id, "EASYSIGN_DOCS_KEK_ID"), key: decodeKek(kek, "EASYSIGN_DOCS_KEK") }, previous);
}

export const isEnvelope = (raw: Buffer): boolean => raw.length >= MAGIC.length && raw.subarray(0, MAGIC.length).equals(MAGIC);

interface ParsedEnvelope {
  kekId: string;
  header: Buffer;
  wrapIv: Buffer;
  wrapTag: Buffer;
  wrappedDek: Buffer;
  body: Buffer; // iv | tag | ciphertext
}

const failed = (why: string) => new EnvelopeError("DECRYPT_FAILED", `The stored document could not be decrypted: ${why}.`);

function parse(raw: Buffer): ParsedEnvelope {
  if (!isEnvelope(raw) || raw.length < MAGIC.length + 2) throw failed("it is not an encrypted envelope");
  if (raw[MAGIC.length] !== ENVELOPE_VERSION) throw failed(`envelope version ${raw[MAGIC.length]} is not supported`);
  const idLength = raw[MAGIC.length + 1];
  const headerEnd = MAGIC.length + 2 + idLength;
  if (raw.length < headerEnd + IV_BYTES + TAG_BYTES + KEY_BYTES + IV_BYTES + TAG_BYTES) throw failed("the envelope is truncated");
  const kekId = raw.subarray(MAGIC.length + 2, headerEnd).toString("latin1");
  if (!KEK_ID.test(kekId)) throw failed("the key id in the header is malformed");
  let at = headerEnd;
  const take = (n: number) => raw.subarray(at, (at += n));
  return { kekId, header: raw.subarray(0, headerEnd), wrapIv: take(IV_BYTES), wrapTag: take(TAG_BYTES), wrappedDek: take(KEY_BYTES), body: raw.subarray(at) };
}

const hashBytes = (hash: string) => Buffer.from(hash, "hex");
const headerFor = (kekId: string) => Buffer.concat([MAGIC, Buffer.from([ENVELOPE_VERSION, Buffer.byteLength(kekId, "latin1")]), Buffer.from(kekId, "latin1")]);
const bodyAad = (hash: string) => Buffer.concat([MAGIC, Buffer.from([ENVELOPE_VERSION]), hashBytes(hash)]);

function gcmSeal(key: Buffer, aad: Buffer, plain: Buffer): { iv: Buffer; tag: Buffer; data: Buffer } {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), data };
}

function gcmOpen(key: Buffer, aad: Buffer, iv: Buffer, tag: Buffer, data: Buffer, why: string): Buffer {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    throw failed(why);
  }
}

function wrapDek(dek: Buffer, hash: string, keyring: DocumentKeyring): Buffer {
  const header = headerFor(keyring.currentId);
  const wrap = gcmSeal(keyring.keys.get(keyring.currentId)!, Buffer.concat([header, hashBytes(hash)]), dek);
  return Buffer.concat([header, wrap.iv, wrap.tag, wrap.data]);
}

function unwrapDek(envelope: ParsedEnvelope, hash: string, keyring: DocumentKeyring | undefined): Buffer {
  const kek = keyring?.keys.get(envelope.kekId);
  if (!kek) throw new EnvelopeError("KEY_UNAVAILABLE", `The stored document is encrypted with key "${envelope.kekId}", which is not configured (EASYSIGN_DOCS_KEK / EASYSIGN_DOCS_KEK_PREVIOUS).`);
  return gcmOpen(kek, Buffer.concat([envelope.header, hashBytes(hash)]), envelope.wrapIv, envelope.wrapTag, envelope.wrappedDek, "the key does not match or the header was altered");
}

/** Id of the KEK that wraps this envelope. */
export const envelopeKekId = (raw: Buffer): string => parse(raw).kekId;

/** Encrypts `plain` (whose SHA-256 is `hash`, lowercase hex) under a fresh DEK wrapped with the current KEK. */
export function sealDocument(plain: Buffer, hash: string, keyring: DocumentKeyring): Buffer {
  const dek = randomBytes(KEY_BYTES);
  try {
    const body = gcmSeal(dek, bodyAad(hash), plain);
    return Buffer.concat([wrapDek(dek, hash, keyring), body.iv, body.tag, body.data]);
  } finally {
    dek.fill(0);
  }
}

/** Decrypts an envelope stored under `hash`. The caller still checks the plaintext against the hash. */
export function openDocument(raw: Buffer, hash: string, keyring: DocumentKeyring | undefined): Buffer {
  const envelope = parse(raw);
  const dek = unwrapDek(envelope, hash, keyring);
  try {
    const { body } = envelope;
    return gcmOpen(dek, bodyAad(hash), body.subarray(0, IV_BYTES), body.subarray(IV_BYTES, IV_BYTES + TAG_BYTES), body.subarray(IV_BYTES + TAG_BYTES), "the content was altered");
  } finally {
    dek.fill(0);
  }
}

/** Rewraps the DEK with the current KEK without touching the encrypted body. */
export function rewrapDocument(raw: Buffer, hash: string, keyring: DocumentKeyring): Buffer {
  const envelope = parse(raw);
  const dek = unwrapDek(envelope, hash, keyring);
  try {
    return Buffer.concat([wrapDek(dek, hash, keyring), envelope.body]);
  } finally {
    dek.fill(0);
  }
}
