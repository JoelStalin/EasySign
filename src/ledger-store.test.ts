import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileLedgerStore, GENESIS, LedgerChainError, assertChain, type LedgerDefinition, type LedgerRecord } from "./storage/ledger-store.js";
import { CONSENT_LEDGER, ConsentError, ConsentLedger, type ConsentPayload } from "./services/consent-ledger.js";
import { DEFAULT_MIGRATIONS_DIR, loadMigrations } from "./storage/migrate.js";
import { buildApp } from "./app.js";

interface Note { text: string }
const NOTES: LedgerDefinition<Note> = {
  name: "notes",
  hash: (r) => createHash("sha256").update(JSON.stringify([r.seq, r.type, r.at, r.tenantId, r.payload.text, r.prevHash])).digest("hex"),
  canonical: (p) => ({ text: String(p.text) }),
};
const AT = "2026-11-12T10:00:00.000Z";
const tmp = (name: string) => join(mkdtempSync(join(tmpdir(), "easysign-ledger-")), name);

test("a ledger keeps one chain across tenants and only returns the asked tenant's events", async () => {
  const s = new FileLedgerStore(NOTES);
  assert.equal(s.kind, "memory");
  const a1 = await s.append("a", { type: "note", at: AT, payload: { text: "one" } });
  const b1 = await s.append("b", { type: "note", at: AT, payload: { text: "two" } });
  const a2 = await s.append("a", { type: "note", at: AT, payload: { text: "three" } });
  assert.deepEqual([a1.seq, b1.seq, a2.seq], [1, 2, 3]);
  assert.equal(a1.prevHash, GENESIS);
  assert.equal(b1.prevHash, a1.hash);
  assert.equal(a2.prevHash, b1.hash);
  assert.deepEqual((await s.readAll("a")).map((r) => r.payload.text), ["one", "three"]);
  assert.deepEqual((await s.readAll("b")).map((r) => r.payload.text), ["two"]);
  assert.deepEqual(await s.readAll("c"), []);
  assert.equal(await s.verify(), true);
  assert.deepEqual(await s.head(), { seq: 3, hash: a2.hash });
  assert.deepEqual((await s.readEverything()).map((r) => r.seq), [1, 2, 3]);
  assert.deepEqual(await new FileLedgerStore(NOTES).head(), { seq: 0, hash: GENESIS });
  await assert.rejects(() => s.append("", { type: "note", at: AT, payload: { text: "x" } }), /tenantId is required/);
  await assert.rejects(() => s.append("a", { type: "note", at: AT, payload: { text: "x", seq: 9 } as Note }), /reserved/);
});

test("the file store reloads its events and refuses a file that was altered", async () => {
  const file = tmp("notes.jsonl");
  const s = new FileLedgerStore(NOTES, { filePath: file });
  assert.equal(s.kind, "file");
  await s.append("a", { type: "note", at: AT, payload: { text: "one" } });
  await s.append("b", { type: "note", at: AT, payload: { text: "two" } });
  assert.deepEqual((await new FileLedgerStore(NOTES, { filePath: file }).readAll("b")).map((r) => r.payload.text), ["two"]);

  const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
  writeFileSync(file, lines[1] + "\n"); // first event removed
  assert.throws(() => new FileLedgerStore(NOTES, { filePath: file }), (e: unknown) => e instanceof LedgerChainError && e.ledger === "notes" && e.seq === 2);
  writeFileSync(file, lines.join("\n").replace("two", "TWO") + "\n"); // content edited
  assert.throws(() => new FileLedgerStore(NOTES, { filePath: file }), LedgerChainError);
});

test("a tenant's partial view is still checked: hashes, order, and links between consecutive events", async () => {
  const s = new FileLedgerStore(NOTES);
  for (const [tenant, text] of [["a", "1"], ["a", "2"], ["b", "3"], ["a", "4"]]) await s.append(tenant, { type: "note", at: AT, payload: { text } });
  const view = await s.readAll("a"); // seq 1, 2, 4
  assert.doesNotThrow(() => assertChain(NOTES, view, false));
  assert.throws(() => assertChain(NOTES, view, true), LedgerChainError, "a partial view is not a complete chain");
  const edited = view.map((r, i) => (i === 2 ? { ...r, payload: { text: "forged" } } : r));
  assert.throws(() => assertChain(NOTES, edited, false), (e: unknown) => e instanceof LedgerChainError && e.seq === 4);
  assert.throws(() => assertChain(NOTES, [view[1], view[0], view[2]], false), LedgerChainError, "out of order");
  const rehash = (r: LedgerRecord<Note>, prevHash: string): LedgerRecord<Note> => { const { hash: _h, ...core } = { ...r, prevHash }; return { ...core, hash: NOTES.hash(core) }; };
  assert.throws(() => assertChain(NOTES, [view[0], rehash(view[1], "f".repeat(64)), view[2]], false), (e: unknown) => e instanceof LedgerChainError && e.seq === 2, "a re-hashed event no longer links to its predecessor");
  assert.throws(() => assertChain(NOTES, [rehash(view[0], "f".repeat(64))], false), LedgerChainError, "the first event must start at the genesis hash");
});

test("consent files written before LedgerStore still load, and new lines keep the same flat format", async () => {
  // A line exactly as the previous implementation wrote it (same key order and hash formula).
  const core = { seq: 1, type: "granted", at: AT, tenantId: "t1", subjectId: "s1", purpose: "marketing", textVersion: "v1", textHash: "a".repeat(64), evidence: { channel: "web", ip: "203.0.113.5" }, prevHash: GENESIS };
  const hash = createHash("sha256").update(JSON.stringify([core.seq, core.type, core.at, core.tenantId, core.subjectId, core.purpose, core.textVersion, core.textHash, core.evidence, core.prevHash])).digest("hex");
  const file = tmp("consents.jsonl");
  writeFileSync(file, JSON.stringify({ ...core, hash }) + "\n");

  const ledger = new ConsentLedger({ filePath: file, now: () => new Date(AT) });
  assert.equal(await ledger.hasConsent("t1", "s1", "marketing"), true);
  const w = await ledger.withdraw("t1", "s1", "marketing", { channel: "web" });
  assert.equal(w.seq, 2);
  assert.equal(w.prevHash, hash);
  const written = JSON.parse(readFileSync(file, "utf8").split("\n").filter(Boolean)[1]) as Record<string, unknown>;
  assert.deepEqual(Object.keys(written), ["seq", "type", "at", "tenantId", "subjectId", "purpose", "textVersion", "textHash", "evidence", "prevHash", "hash"]);
  assert.deepEqual(written, w);
  assert.equal(await new ConsentLedger({ filePath: file }).verifyChain(), true);
});

test("the consent hash survives a jsonb round trip, which reorders keys", () => {
  const payload: ConsentPayload = { subjectId: "s1", purpose: "marketing", textVersion: "v1", textHash: "b".repeat(64), evidence: { channel: "web", ip: "203.0.113.5", userAgent: "ua" } };
  const core = { seq: 7, type: "granted", at: AT, tenantId: "t1", payload, prevHash: GENESIS };
  // jsonb returns keys sorted by length, then alphabetically
  const fromJsonb = { evidence: { ip: "203.0.113.5", channel: "web", userAgent: "ua" }, purpose: "marketing", textHash: "b".repeat(64), subjectId: "s1", textVersion: "v1" };
  assert.notEqual(JSON.stringify(fromJsonb), JSON.stringify(payload));
  assert.equal(CONSENT_LEDGER.hash({ ...core, payload: CONSENT_LEDGER.canonical(fromJsonb) }), CONSENT_LEDGER.hash(core));
  // optional evidence fields stay absent instead of becoming null or undefined keys
  assert.deepEqual(Object.keys(CONSENT_LEDGER.canonical({ ...fromJsonb, evidence: { channel: "web" } }).evidence), ["channel"]);
});

test("a broken store surfaces as CHAIN_BROKEN from the consent ledger", async () => {
  const boom = new LedgerChainError("consent", 3, "altered");
  const ledger = new ConsentLedger({ store: { kind: "postgres", append: async () => { throw new Error("unused"); }, readAll: async () => { throw boom; }, verify: async () => false, head: async () => ({ seq: 3, hash: GENESIS }) } });
  await assert.rejects(() => ledger.hasConsent("t1", "s1", "marketing"), (e: unknown) => e instanceof ConsentError && e.code === "CHAIN_BROKEN");
  await assert.rejects(() => ledger.history("t1", "s1"), (e: unknown) => e instanceof ConsentError && e.code === "CHAIN_BROKEN");
  assert.equal(await ledger.verifyChain("t1"), false);
});

test("migrations are numbered 1..n, checksummed, and badly named files are rejected", () => {
  const real = loadMigrations(DEFAULT_MIGRATIONS_DIR);
  assert.ok(real.length >= 1);
  assert.equal(real[0].version, 1);
  assert.equal(real[0].name, "ledger_events");
  assert.match(real[0].checksum, /^[0-9a-f]{64}$/);
  assert.match(real[0].sql, /FORCE ROW LEVEL SECURITY/);

  const dir = mkdtempSync(join(tmpdir(), "easysign-migrations-"));
  writeFileSync(join(dir, "001_a.sql"), "SELECT 1;");
  writeFileSync(join(dir, "003_c.sql"), "SELECT 3;");
  assert.throws(() => loadMigrations(dir), /without gaps/);
  writeFileSync(join(dir, "002_b.sql"), "SELECT 2;");
  assert.deepEqual(loadMigrations(dir).map((m) => m.version), [1, 2, 3]);
  writeFileSync(join(dir, "Bad Name.sql"), "SELECT 0;");
  assert.throws(() => loadMigrations(dir), /must be named/);
});

test("without a database URL the API keeps the consent ledger in memory", async () => {
  const app = buildApp({ registryAdminToken: "tok", disclosure: undefined, databaseUrl: undefined });
  const h = { authorization: "Bearer tok" };
  const payload = { tenantId: "t1", subjectId: "s1", purpose: "marketing", textVersion: "v1", text: "acepto", evidence: { channel: "web" } };
  assert.equal((await app.inject({ method: "POST", url: "/v1/consents", headers: h, payload })).statusCode, 201);
  assert.equal((await app.inject({ method: "GET", url: "/v1/consents/t1/s1", headers: h })).json().marketingAllowed, true);
  await app.close();
});
