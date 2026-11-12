import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdtempSync, appendFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { buildApp } from "./app.js";
import { CONSENT_LEDGER, ConsentError, ConsentLedger } from "./services/consent-ledger.js";
import { GENESIS, LedgerChainError } from "./storage/ledger-store.js";
import { DEFAULT_MIGRATIONS_DIR, runMigrations } from "./storage/migrate.js";
import { PostgresLedgerStore, UnsafeDatabaseRoleError, assertSafeApplicationRole, verifyFullChain } from "./storage/postgres-ledger-store.js";

/**
 * Integration tests against a real PostgreSQL. They need EASYSIGN_TEST_DATABASE_URL pointing at a THROWAWAY server
 * with a superuser (for example a temporary `postgres:16` container): the suite creates its own database and roles
 * and drops them at the end. Without the variable the whole suite is skipped.
 */
const ADMIN_URL = process.env.EASYSIGN_TEST_DATABASE_URL;
const id = randomBytes(5).toString("hex");
const DB = `easysign_it_${id}`;
const OWNER = `es_owner_${id}`;
const APP = `es_app_${id}`;
const AUDITOR = `es_auditor_${id}`;
const password = randomBytes(18).toString("hex"); // generated per run, never stored

const urlFor = (user: string, database = DB): string => {
  const u = new URL(ADMIN_URL as string);
  u.username = user; u.password = password; u.pathname = `/${database}`;
  return u.toString();
};
const sqlState = (code: string) => (e: unknown) => (e as { code?: string }).code === code;
const ev = { channel: "web", ip: "203.0.113.5", userAgent: "integration-test" };
const grantInput = (tenantId: string, subjectId: string, purpose: "marketing" | "personal_data_processing" = "marketing") => ({ tenantId, subjectId, purpose, textVersion: "v1", text: "Acepto.", evidence: ev });

describe("PostgreSQL ledger with per-tenant row level security", { skip: ADMIN_URL ? false : "EASYSIGN_TEST_DATABASE_URL is not set" }, () => {
  let admin: pg.Client;      // superuser on the throwaway server, only for setup, teardown and deliberate tampering
  let owner: pg.Client;      // schema owner: runs the migrations
  let appPool: pg.Pool;      // what the API uses: member of easysign_app only
  let auditorPool: pg.Pool;  // member of easysign_auditor only
  let ledger: ConsentLedger;

  /** Runs raw SQL as the application role inside a transaction, optionally with app.tenant_id set, then rolls back. */
  const asApp = async <T>(tenantId: string | undefined, work: (c: pg.PoolClient) => Promise<T>): Promise<T> => {
    const c = await appPool.connect();
    try {
      await c.query("BEGIN");
      if (tenantId !== undefined) await c.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      return await work(c);
    } finally {
      await c.query("ROLLBACK");
      c.release();
    }
  };
  const head = async () => (await auditorPool.query<{ last_seq: string; last_hash: string }>("SELECT last_seq, last_hash FROM ledger_heads WHERE ledger = 'consent'")).rows[0];

  before(async () => {
    admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE ROLE ${OWNER} LOGIN CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
    await admin.query(`CREATE DATABASE ${DB} OWNER ${OWNER}`);

    owner = new pg.Client({ connectionString: urlFor(OWNER) });
    await owner.connect();
    assert.deepEqual(await runMigrations(owner), readdirSync(DEFAULT_MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).map((_, i) => i + 1));

    // Login roles: nothing but membership in the group roles the migration created.
    await admin.query(`CREATE ROLE ${APP} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '${password}' IN ROLE easysign_app`);
    await admin.query(`CREATE ROLE ${AUDITOR} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '${password}' IN ROLE easysign_auditor`);
    appPool = new pg.Pool({ connectionString: urlFor(APP), max: 8 });
    auditorPool = new pg.Pool({ connectionString: urlFor(AUDITOR), max: 2 });
    ledger = new ConsentLedger({ store: new PostgresLedgerStore(appPool, CONSENT_LEDGER) });
  });

  after(async () => {
    await appPool?.end();
    await auditorPool?.end();
    await owner?.end();
    if (!admin) return;
    await admin.query(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`);
    for (const role of [APP, AUDITOR, OWNER]) await admin.query(`DROP ROLE IF EXISTS ${role}`);
    await admin.end();
  });

  test("migrations are recorded once, re-running applies nothing, and an edited migration is refused", async () => {
    assert.deepEqual(await runMigrations(owner), []);
    const rows = (await owner.query("SELECT version, name, checksum FROM schema_migrations ORDER BY version")).rows;
    assert.equal(rows[0].version, 1);
    assert.equal(rows[0].name, "ledger_events");

    const dir = mkdtempSync(join(tmpdir(), "easysign-mig-"));
    for (const f of readdirSync(DEFAULT_MIGRATIONS_DIR)) copyFileSync(join(DEFAULT_MIGRATIONS_DIR, f), join(dir, f));
    appendFileSync(join(dir, "001_ledger_events.sql"), "\n-- edited after release\n");
    await assert.rejects(() => runMigrations(owner, dir), /checksum mismatch/);
  });

  test("the application role is safe, and unsafe roles are refused before any tenant data is touched", async () => {
    await assertSafeApplicationRole(appPool);
    const attrs = (await appPool.query("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user")).rows[0];
    assert.deepEqual(attrs, { rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false });

    for (const [user, why] of [[OWNER, /owns ledger_events/], [AUDITOR, /easysign_app/]] as const) {
      const pool = new pg.Pool({ connectionString: urlFor(user), max: 1 });
      try {
        const unsafe = new ConsentLedger({ store: new PostgresLedgerStore(pool, CONSENT_LEDGER) });
        if (user === OWNER) {
          await assert.rejects(() => unsafe.grant(grantInput("tenant-a", "x")), (e: unknown) => e instanceof UnsafeDatabaseRoleError && why.test(e.message));
          await assert.rejects(() => unsafe.history("tenant-a", "x"), UnsafeDatabaseRoleError);
        } else {
          // the auditor passes the attribute check but has no INSERT and no tenant policy for writing
          await assert.rejects(() => unsafe.grant(grantInput("tenant-a", "x")), sqlState("42501"));
        }
      } finally { await pool.end(); }
    }
    const superPool = new pg.Pool({ connectionString: ((): string => { const u = new URL(ADMIN_URL as string); u.pathname = `/${DB}`; return u.toString(); })(), max: 1 });
    try {
      await assert.rejects(() => new PostgresLedgerStore(superPool, CONSENT_LEDGER).readAll("tenant-a"), (e: unknown) => e instanceof UnsafeDatabaseRoleError && /superuser/.test(e.message) && /BYPASSRLS/.test(e.message));
    } finally { await superPool.end(); }
    assert.equal((await head()), undefined, "refused roles wrote nothing");
  });

  test("the consent ledger works on PostgreSQL and each tenant only gets its own events", async () => {
    assert.equal(await ledger.hasConsent("tenant-a", "s1", "marketing"), false);
    const g = await ledger.grant(grantInput("tenant-a", "s1"));
    assert.equal(g.seq, 1);
    assert.equal(g.prevHash, GENESIS);
    await ledger.grant(grantInput("tenant-b", "s1", "personal_data_processing"));
    await ledger.grant(grantInput("tenant-a", "s2"));
    assert.equal(await ledger.hasConsent("tenant-a", "s1", "marketing"), true);
    assert.equal(await ledger.hasConsent("tenant-b", "s1", "marketing"), false, "same subject id, other tenant");
    const w = await ledger.withdraw("tenant-a", "s1", "marketing", ev);
    assert.equal(w.seq, 4);
    assert.equal(await ledger.hasConsent("tenant-a", "s1", "marketing"), false);
    await assert.rejects(() => ledger.withdraw("tenant-b", "s1", "marketing", ev), (e: unknown) => e instanceof ConsentError && e.code === "NOT_GRANTED");

    const a = await ledger.history("tenant-a", "s1");
    assert.deepEqual(a.map((e) => [e.seq, e.type]), [[1, "granted"], [4, "withdrawn"]]);
    assert.deepEqual(a[0], g, "what is read back equals what was written (timestamp, evidence order, hashes)");
    assert.ok(a.every((e) => e.tenantId === "tenant-a"));
    assert.deepEqual((await ledger.history("tenant-b", "s1")).map((e) => e.seq), [2]);
    assert.deepEqual(await ledger.history("tenant-c", "s1"), []);
    assert.equal(await ledger.verifyChain("tenant-a"), true);
    assert.equal(await ledger.verifyChain("tenant-b"), true);
    await assert.rejects(() => ledger.verifyChain(), /easysign_auditor/);
    await assert.rejects(() => ledger.history("", "s1"), /tenantId is required/);
  });

  test("direct SQL under the application role cannot read another tenant's rows", async () => {
    const total = Number((await auditorPool.query("SELECT count(*) AS n FROM ledger_events")).rows[0].n);
    assert.equal(total, 4);

    // no tenant in the transaction: nothing is visible
    assert.equal((await asApp(undefined, (c) => c.query("SELECT * FROM ledger_events"))).rowCount, 0);
    assert.equal((await asApp("", (c) => c.query("SELECT * FROM ledger_events"))).rowCount, 0);
    // autocommit, outside any transaction, right after other transactions set the tenant on pooled connections
    for (let i = 0; i < 8; i++) assert.equal((await appPool.query("SELECT * FROM ledger_events")).rowCount, 0, "SET LOCAL does not leak to the next user of the connection");

    await asApp("tenant-b", async (c) => {
      assert.deepEqual((await c.query("SELECT DISTINCT tenant_id FROM ledger_events")).rows, [{ tenant_id: "tenant-b" }]);
      assert.equal((await c.query("SELECT * FROM ledger_events WHERE tenant_id = 'tenant-a'")).rowCount, 0);
      assert.equal((await c.query("SELECT * FROM ledger_events WHERE tenant_id <> 'tenant-b' OR true")).rowCount, 1);
      assert.equal(Number((await c.query("SELECT count(*) AS n FROM ledger_events")).rows[0].n), 1);
      assert.equal((await c.query("SELECT * FROM ledger_events WHERE payload->>'subjectId' = 's2'")).rowCount, 0, "tenant-a's subject s2 is invisible");
    });
    // a tenant id built to look like SQL is just a string that matches nothing
    assert.equal((await asApp("tenant-a' OR '1'='1", (c) => c.query("SELECT * FROM ledger_events"))).rowCount, 0);

    // the role cannot switch the protection off or step into another role
    await assert.rejects(() => asApp("tenant-b", async (c) => { await c.query("SET LOCAL row_security = off"); return c.query("SELECT * FROM ledger_events"); }), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query(`SET LOCAL ROLE ${OWNER}`)), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query("SET LOCAL ROLE easysign_auditor")), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query("ALTER TABLE ledger_events DISABLE ROW LEVEL SECURITY")), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query("DROP POLICY tenant_read ON ledger_events")), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query("CREATE POLICY open ON ledger_events FOR SELECT USING (true)")), sqlState("42501"));
    await assert.rejects(() => asApp("tenant-b", (c) => c.query("CREATE TABLE copy AS SELECT 1")), sqlState("42501"));
  });

  test("direct SQL under the application role cannot write, change or delete another tenant's rows", async () => {
    const before = await head();
    assert.equal(Number(before.last_seq), 4);
    const insert = (c: pg.PoolClient, tenant: string, seq = 5, prev = before.last_hash) => c.query(
      "INSERT INTO ledger_events (ledger, seq, tenant_id, type, at, payload, prev_hash, hash) VALUES ('consent', $1, $2, 'granted', now(), '{}'::jsonb, $3, $4)", [seq, tenant, prev, "c".repeat(64)]);

    await assert.rejects(() => asApp("tenant-b", (c) => insert(c, "tenant-a")), sqlState("42501"), "forging a row for another tenant violates the policy");
    await assert.rejects(() => asApp(undefined, (c) => insert(c, "tenant-a")), sqlState("42501"), "no tenant, no write");
    await assert.rejects(() => asApp("", (c) => insert(c, "")), (e: unknown) => ["42501", "23514"].includes((e as { code: string }).code));
    await assert.rejects(() => asApp("tenant-b", (c) => insert(c, "tenant-b", 5, "d".repeat(64))), sqlState("40001"), "an event that does not extend the head is refused by the database");
    await assert.rejects(() => asApp("tenant-b", (c) => insert(c, "tenant-b", 9)), sqlState("40001"));
    await assert.rejects(() => asApp("tenant-b", (c) => insert(c, "tenant-b", 1)), (e: unknown) => ["40001", "23505"].includes((e as { code: string }).code), "an existing sequence number cannot be reused");

    for (const statement of [
      "UPDATE ledger_events SET tenant_id = 'tenant-b'",
      "UPDATE ledger_events SET payload = '{}'::jsonb WHERE tenant_id = 'tenant-b'",
      "DELETE FROM ledger_events",
      "DELETE FROM ledger_events WHERE tenant_id = 'tenant-b'",
      "TRUNCATE ledger_events",
      "UPDATE ledger_heads SET last_seq = 0",
      "DELETE FROM ledger_heads",
      "INSERT INTO ledger_heads VALUES ('other', 0, repeat('0', 64))",
      "SELECT * FROM ledger_events FOR UPDATE",
      "ALTER TABLE ledger_events DISABLE TRIGGER ALL",
      "SET LOCAL session_replication_role = replica",
      "DELETE FROM schema_migrations",
    ]) {
      await assert.rejects(() => asApp("tenant-b", (c) => c.query(statement)), sqlState("42501"), statement);
    }

    // append-only holds for the owner as well, and under FORCE the owner sees no tenant rows at all
    assert.equal((await owner.query("SELECT * FROM ledger_events")).rowCount, 0);
    await owner.query("BEGIN");
    await owner.query("SELECT set_config('app.tenant_id', 'tenant-a', true)");
    assert.equal((await owner.query("SELECT * FROM ledger_events")).rowCount, 0, "the tenant policies are granted to easysign_app only");
    await owner.query("ROLLBACK");
    await assert.rejects(() => owner.query("TRUNCATE ledger_events"), sqlState("42501"));

    assert.deepEqual(await head(), before, "none of the attempts moved the chain");
    assert.equal(Number((await auditorPool.query("SELECT count(*) AS n FROM ledger_events")).rows[0].n), 4);
  });

  test("concurrent writers from several tenants and several ledger instances keep one unbroken chain", async () => {
    const second = new pg.Pool({ connectionString: urlFor(APP), max: 6 });
    try {
      const other = new ConsentLedger({ store: new PostgresLedgerStore(second, CONSENT_LEDGER) }); // a second API process
      const N = 60;
      const events = await Promise.all(Array.from({ length: N }, (_, i) => (i % 2 ? ledger : other).grant(grantInput(`tenant-${"abc"[i % 3]}`, `bulk-${i}`))));
      assert.deepEqual(events.map((e) => e.seq).sort((x, y) => x - y), Array.from({ length: N }, (_, i) => i + 5), "no gaps, no duplicates");

      const full = await verifyFullChain(auditorPool, CONSENT_LEDGER);
      assert.equal(full.events, N + 4);
      assert.equal(full.headHash, (await head()).last_hash);
      for (const t of ["tenant-a", "tenant-b", "tenant-c"]) assert.equal(await ledger.verifyChain(t), true);
      assert.equal((await ledger.history("tenant-c", "bulk-2")).length, 1);
      assert.equal((await ledger.history("tenant-a", "bulk-2")).length, 0);

      // the application role cannot verify (or read) the whole chain, even if it tries
      await assert.rejects(() => verifyFullChain(appPool, CONSENT_LEDGER), (e: unknown) => e instanceof LedgerChainError && /cannot see the whole chain/.test(e.message));
      // and the auditor is read-only
      await assert.rejects(() => auditorPool.query("DELETE FROM ledger_events"), sqlState("42501"));
    } finally { await second.end(); }
  });

  test("the HTTP API uses PostgreSQL when a database URL is configured, and refuses to start with an unsafe role", async () => {
    const app = buildApp({ registryAdminToken: "tok", disclosure: undefined, databaseUrl: urlFor(APP) });
    try {
      await app.ready();
      const h = { authorization: "Bearer tok" };
      const body = { tenantId: "tenant-http", subjectId: "s1", purpose: "marketing", textVersion: "v1", text: "acepto", evidence: { channel: "web" } };
      const created = await app.inject({ method: "POST", url: "/v1/consents", headers: h, payload: body });
      assert.equal(created.statusCode, 201);
      const read = (await app.inject({ method: "GET", url: "/v1/consents/tenant-http/s1", headers: h })).json();
      assert.equal(read.marketingAllowed, true);
      assert.deepEqual(read.history, [created.json()]);
      assert.equal((await app.inject({ method: "GET", url: "/v1/consents/tenant-a/s1", headers: h })).json().history.every((e: { tenantId: string }) => e.tenantId === "tenant-a"), true);
      assert.equal((await app.inject({ method: "POST", url: "/v1/consents/withdraw", headers: h, payload: { tenantId: "tenant-http", subjectId: "s1", purpose: "marketing", evidence: { channel: "web" } } })).statusCode, 200);
      // a second instance (another process or a restart) sees the same state
      assert.equal(await ledger.hasConsent("tenant-http", "s1", "marketing"), false);
      assert.equal((await ledger.history("tenant-http", "s1")).length, 2);
    } finally { await app.close(); }

    const unsafe = buildApp({ registryAdminToken: "tok", disclosure: undefined, databaseUrl: urlFor(OWNER) });
    await assert.rejects(async () => { await unsafe.ready(); }, UnsafeDatabaseRoleError);
    await unsafe.close();
  });

  test("tampering done with superuser rights is detected when the ledger is read", async () => {
    await verifyFullChain(auditorPool, CONSENT_LEDGER);
    // Only a superuser can get past the append-only trigger, by disabling it.
    const su = new pg.Client({ connectionString: ((): string => { const u = new URL(ADMIN_URL as string); u.pathname = `/${DB}`; return u.toString(); })() });
    await su.connect();
    try {
      await su.query("BEGIN");
      await su.query("SET LOCAL session_replication_role = replica");
      const changed = await su.query("UPDATE ledger_events SET type = 'granted' WHERE ledger = 'consent' AND seq = 4");
      assert.equal(changed.rowCount, 1);
      await su.query("COMMIT");
    } finally { await su.end(); }

    await assert.rejects(() => ledger.hasConsent("tenant-a", "s1", "marketing"), (e: unknown) => e instanceof ConsentError && e.code === "CHAIN_BROKEN");
    assert.equal(await ledger.verifyChain("tenant-a"), false);
    assert.equal(await ledger.verifyChain("tenant-b"), true, "other tenants are unaffected and learn nothing about it");
    await assert.rejects(() => verifyFullChain(auditorPool, CONSENT_LEDGER), (e: unknown) => e instanceof LedgerChainError && e.seq === 4);
  });
});
