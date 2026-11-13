import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DocumentKeyError, createKeyring, envelopeKekId, isEnvelope, loadDocumentKeyring } from "./services/document-crypto.js";
import { DocumentError, DocumentStore, documentStoreFromEnv, sha256Hex } from "./services/document-store.js";

// Keys are generated for each run; no key material lives in the repository.
const key = () => randomBytes(32);
const b64 = () => key().toString("base64");
const PDF = Buffer.from("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\nCONFIDENCIAL-contrato-de-prueba\n");
const HASH = sha256Hex(PDF);
const TEXT = Buffer.from("Acuerdo de confidencialidad ñ");
const tmp = () => mkdtempSync(join(tmpdir(), "easysign-enc-"));
const code = (c: string) => (e: unknown) => e instanceof DocumentError && e.code === c;
const keyError = (pattern: RegExp) => (e: unknown) => e instanceof DocumentKeyError && pattern.test(e.message);

test("round trip: the file on disk is an envelope without the plaintext, and reads back intact under its plaintext hash", () => {
  const dir = tmp();
  const store = new DocumentStore(dir, createKeyring({ id: "k1", key: key() }));
  assert.equal(store.encrypted, true);
  const put = store.put(PDF);
  assert.equal(put.hash, HASH); // the hash is still the plaintext's
  assert.deepEqual(readdirSync(dir), [HASH]); // no temporary file is left behind
  const raw = readFileSync(join(dir, HASH));
  assert.ok(isEnvelope(raw));
  assert.equal(envelopeKekId(raw), "k1");
  assert.ok(!raw.includes("CONFIDENCIAL"), "plaintext must not be on disk");
  assert.ok(!raw.includes("%PDF"));
  assert.deepEqual(store.get(HASH), { bytes: PDF, contentType: "application/pdf" });

  // a fresh data key and nonces every time: storing the same document twice gives different bytes
  store.put(PDF);
  assert.notDeepEqual(readFileSync(join(dir, HASH)), raw);
  assert.deepEqual(store.get(HASH).bytes, PDF);
});

test("a tampered envelope is refused wherever the change is", () => {
  const dir = tmp();
  const store = new DocumentStore(dir, createKeyring({ id: "k1", key: key() }));
  store.put(PDF);
  const path = join(dir, HASH);
  const original = readFileSync(path);
  const headerEnd = 6 + 2 + 2; // magic, version, id length, "k1"
  const offsets = { version: 6, kekId: 8, wrapIv: headerEnd, wrapTag: headerEnd + 12, wrappedDek: headerEnd + 28, iv: headerEnd + 60, tag: headerEnd + 72, firstCipherByte: headerEnd + 88, lastCipherByte: original.length - 1 };
  for (const [where, at] of Object.entries(offsets)) {
    const altered = Buffer.from(original);
    altered[at] ^= 0x01;
    writeFileSync(path, altered);
    assert.throws(() => store.get(HASH), (e) => code("DECRYPT_FAILED")(e) || (where === "kekId" && code("KEY_UNAVAILABLE")(e)), `altered ${where}`);
  }
  for (const length of [7, headerEnd + 20, headerEnd + 87]) {
    writeFileSync(path, original.subarray(0, length));
    assert.throws(() => store.get(HASH), code("DECRYPT_FAILED"), `truncated to ${length}`);
  }
  writeFileSync(path, Buffer.concat([original, Buffer.from([0])]));
  assert.throws(() => store.get(HASH), code("DECRYPT_FAILED"));

  // an intact envelope moved under another document's name does not open either
  writeFileSync(path, original);
  const other = store.put(TEXT).hash;
  renameSync(path, join(dir, other));
  assert.throws(() => store.get(other), code("DECRYPT_FAILED"));
});

test("the wrong key does not open a document: same id with another key, unknown id, or no key at all", () => {
  const dir = tmp();
  new DocumentStore(dir, createKeyring({ id: "k1", key: key() })).put(PDF);
  assert.throws(() => new DocumentStore(dir, createKeyring({ id: "k1", key: key() })).get(HASH), code("DECRYPT_FAILED"));
  assert.throws(() => new DocumentStore(dir, createKeyring({ id: "k2", key: key() })).get(HASH), code("KEY_UNAVAILABLE"));
  assert.throws(() => new DocumentStore(dir).get(HASH), code("KEY_UNAVAILABLE"));
});

test("rotation: a previous KEK still opens old documents, and re-encryption moves them to the current one", () => {
  const dir = tmp();
  const k1 = key();
  const k2 = key();
  new DocumentStore(dir, createKeyring({ id: "2026-11", key: k1 })).put(PDF);
  const before = readFileSync(join(dir, HASH));

  const rotated = new DocumentStore(dir, createKeyring({ id: "2027-01", key: k2 }, [{ id: "2026-11", key: k1 }]));
  assert.deepEqual(rotated.get(HASH).bytes, PDF); // readable before re-encrypting
  const text = rotated.put(TEXT).hash; // new documents go under the current key
  assert.equal(envelopeKekId(readFileSync(join(dir, text))), "2027-01");

  assert.deepEqual(rotated.reencryptAll(), { encrypted: 0, rewrapped: 1, unchanged: 1, failed: [] });
  const after = readFileSync(join(dir, HASH));
  assert.equal(envelopeKekId(after), "2027-01");
  assert.deepEqual(after.subarray(after.length - PDF.length - 28), before.subarray(before.length - PDF.length - 28), "only the data key is rewrapped; the body is not rewritten");
  assert.deepEqual(rotated.reencryptAll(), { encrypted: 0, rewrapped: 0, unchanged: 2, failed: [] }); // running again changes nothing
  assert.deepEqual(readdirSync(dir).sort(), [HASH, text].sort());

  // the old key can now be retired
  const onlyNew = new DocumentStore(dir, createKeyring({ id: "2027-01", key: k2 }));
  assert.deepEqual(onlyNew.get(HASH).bytes, PDF);
  assert.deepEqual(onlyNew.get(text).bytes, TEXT);
  assert.throws(() => new DocumentStore(dir, createKeyring({ id: "2026-11", key: k1 })).get(HASH), code("KEY_UNAVAILABLE"));
});

test("re-encryption reports what it cannot open and leaves it untouched", () => {
  const dir = tmp();
  new DocumentStore(dir, createKeyring({ id: "old", key: key() })).put(PDF);
  const before = readFileSync(join(dir, HASH));
  const store = new DocumentStore(dir, createKeyring({ id: "new", key: key() })); // the old key was not provided
  const report = store.reencryptAll();
  assert.equal(report.failed.length, 1);
  assert.equal(report.failed[0].hash, HASH);
  assert.match(report.failed[0].reason, /"old"/);
  assert.deepEqual(readFileSync(join(dir, HASH)), before);
  assert.throws(() => new DocumentStore(dir).reencryptAll(), keyError(/needs a key/));
  assert.throws(() => new DocumentStore(undefined, createKeyring({ id: "new", key: key() })).reencryptAll(), keyError(/no directory/));
});

test("unencrypted legacy files stay readable and are encrypted by the migration", () => {
  const dir = tmp();
  new DocumentStore(dir).put(PDF); // written before encryption was turned on
  assert.deepEqual(readFileSync(join(dir, HASH)), PDF);
  const bad = "0".repeat(64);
  writeFileSync(join(dir, bad), "plain text that does not match its name");
  writeFileSync(join(dir, "notes.txt"), "not a document"); // names that are not hashes are ignored

  const store = new DocumentStore(dir, createKeyring({ id: "k1", key: key() }));
  assert.deepEqual(store.get(HASH).bytes, PDF); // transparent read
  assert.throws(() => store.get(bad), code("NOT_FOUND")); // a legacy file that does not match its hash is still refused

  const report = store.reencryptAll();
  assert.equal(report.encrypted, 1);
  assert.deepEqual(report.failed.map((f) => f.hash), [bad]);
  assert.ok(isEnvelope(readFileSync(join(dir, HASH))));
  assert.deepEqual(store.get(HASH).bytes, PDF);
  assert.equal(readFileSync(join(dir, "notes.txt"), "utf8"), "not a document");
  assert.equal(readFileSync(join(dir, bad), "utf8"), "plain text that does not match its name");
});

test("configuration: production refuses to start without a key; development continues unencrypted with a warning", () => {
  assert.throws(() => documentStoreFromEnv({ NODE_ENV: "production" }), keyError(/required in production/));
  assert.throws(() => documentStoreFromEnv({ NODE_ENV: "production", EASYSIGN_DOCS_DIR: tmp() }), keyError(/required in production/));

  const warnings: string[] = [];
  const dir = tmp();
  const dev = documentStoreFromEnv({ NODE_ENV: "development", EASYSIGN_DOCS_DIR: dir }, (m) => warnings.push(m));
  assert.equal(dev.encrypted, false);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /WITHOUT encryption/);
  dev.put(PDF);
  assert.deepEqual(readFileSync(join(dir, HASH)), PDF);
  documentStoreFromEnv({}, (m) => warnings.push(m)); // memory only: nothing is at rest, so nothing to warn about
  assert.equal(warnings.length, 1);

  const k = b64();
  const prod = documentStoreFromEnv({ NODE_ENV: "production", EASYSIGN_DOCS_DIR: dir, EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "k1" }, (m) => warnings.push(m));
  assert.equal(prod.encrypted, true);
  assert.equal(warnings.length, 1);
  assert.deepEqual(prod.get(HASH).bytes, PDF); // the file written in development is still served
});

test("configuration: keys are validated and error messages never echo key material", () => {
  const k = b64();
  const old = b64();
  assert.equal(loadDocumentKeyring({}), undefined);
  const ring = loadDocumentKeyring({ EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "2027-01", EASYSIGN_DOCS_KEK_PREVIOUS: ` 2026-11:${old} , 2026-06:${b64()}` })!;
  assert.equal(ring.currentId, "2027-01");
  assert.deepEqual([...ring.keys.keys()], ["2027-01", "2026-11", "2026-06"]);
  assert.deepEqual(ring.keys.get("2026-11"), Buffer.from(old, "base64"));

  const short = randomBytes(16).toString("base64");
  const bad: [NodeJS.ProcessEnv, RegExp][] = [
    [{ EASYSIGN_DOCS_KEK: k }, /EASYSIGN_DOCS_KEK_ID is empty/],
    [{ EASYSIGN_DOCS_KEK: short, EASYSIGN_DOCS_KEK_ID: "k1" }, /exactly 32 bytes/],
    [{ EASYSIGN_DOCS_KEK: "not base64 at all", EASYSIGN_DOCS_KEK_ID: "k1" }, /exactly 32 bytes/],
    [{ EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "bad id" }, /EASYSIGN_DOCS_KEK_ID must be/],
    [{ EASYSIGN_DOCS_KEK_PREVIOUS: `k0:${old}` }, /EASYSIGN_DOCS_KEK is empty/],
    [{ EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "k1", EASYSIGN_DOCS_KEK_PREVIOUS: old }, /id:base64key/],
    [{ EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "k1", EASYSIGN_DOCS_KEK_PREVIOUS: `k0:${short}` }, /exactly 32 bytes/],
    [{ EASYSIGN_DOCS_KEK: k, EASYSIGN_DOCS_KEK_ID: "k1", EASYSIGN_DOCS_KEK_PREVIOUS: `k1:${old}` }, /repeated/],
  ];
  for (const [env, pattern] of bad) {
    assert.throws(() => loadDocumentKeyring(env), (e) => {
      assert.ok(keyError(pattern)(e), `${String(e)} should match ${pattern}`);
      for (const secret of [k, old, short]) assert.ok(!(e as Error).message.includes(secret), "the message must not contain a key");
      return true;
    });
  }
});
