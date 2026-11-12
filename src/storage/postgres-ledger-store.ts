import type pg from "pg";
import { GENESIS, LedgerChainError, assertChain, type LedgerDefinition, type LedgerDraft, type LedgerRecord, type LedgerStore } from "./ledger-store.js";

/**
 * PostgreSQL ledger with per-tenant row level security (backlog ES-006, see docs/POSTGRES_TENANCY.md).
 * Every statement runs inside a transaction that first sets `app.tenant_id` (the equivalent of SET LOCAL), so the
 * policies of `ledger_events` only expose that tenant's rows. The store refuses to work with a role that could
 * bypass those policies.
 */

/** A pool or a single client. */
export interface Queryable {
  query<R extends pg.QueryResultRow>(text: string, values?: unknown[]): Promise<pg.QueryResult<R>>;
}

interface EventRow { seq: string; tenant_id: string; type: string; at: Date; payload: Record<string, unknown>; prev_hash: string; hash: string }
interface Head { seq: number; hash: string }

export class UnsafeDatabaseRoleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeDatabaseRoleError";
  }
}

/** SQLSTATEs that mean another writer extended the chain first: re-read the head and try again. */
const RETRYABLE = new Set(["40001", "23505", "40P01"]);

const toRecord = <P>(definition: LedgerDefinition<P>, row: EventRow): LedgerRecord<P> => ({
  seq: Number(row.seq), type: row.type, at: new Date(row.at).toISOString(), tenantId: row.tenant_id, payload: definition.canonical(row.payload), prevHash: row.prev_hash, hash: row.hash,
});

async function readHead(db: Queryable, ledger: string): Promise<Head> {
  const r = await db.query<{ last_seq: string; last_hash: string }>("SELECT last_seq, last_hash FROM public.ledger_heads WHERE ledger = $1", [ledger]);
  return r.rows[0] ? { seq: Number(r.rows[0].last_seq), hash: r.rows[0].last_hash } : { seq: 0, hash: GENESIS };
}

/**
 * Fails unless the connected role is safe to serve tenants: not a superuser, no BYPASSRLS, not the owner of
 * `ledger_events`, no UPDATE/DELETE/TRUNCATE on it, and the table has row level security enabled and forced.
 */
export async function assertSafeApplicationRole(db: Queryable): Promise<void> {
  const r = await db.query<{ role: string; rolsuper: boolean; rolbypassrls: boolean; exists: boolean; owner: boolean; rls: boolean; forced: boolean; can_rewrite: boolean }>(`
    SELECT current_user AS role, r.rolsuper, r.rolbypassrls,
           c.oid IS NOT NULL AS exists,
           COALESCE(pg_has_role(current_user, c.relowner, 'MEMBER'), false) AS owner,
           COALESCE(c.relrowsecurity, false) AS rls, COALESCE(c.relforcerowsecurity, false) AS forced,
           COALESCE(has_table_privilege(current_user, c.oid, 'UPDATE') OR has_table_privilege(current_user, c.oid, 'DELETE') OR has_table_privilege(current_user, c.oid, 'TRUNCATE'), false) AS can_rewrite
      FROM pg_roles r LEFT JOIN pg_class c ON c.oid = to_regclass('public.ledger_events')
     WHERE r.rolname = current_user`);
  const s = r.rows[0];
  if (!s) throw new UnsafeDatabaseRoleError("Could not read the attributes of the connected database role.");
  if (!s.exists) throw new UnsafeDatabaseRoleError("Table public.ledger_events does not exist: run the migrations first (npm run migrate).");
  const reasons = [
    s.rolsuper && "it is a superuser",
    s.rolbypassrls && "it has BYPASSRLS",
    s.owner && "it owns ledger_events",
    s.can_rewrite && "it can UPDATE, DELETE or TRUNCATE ledger_events",
    !s.rls && "row level security is not enabled on ledger_events",
    !s.forced && "row level security is not forced on ledger_events",
  ].filter(Boolean);
  if (reasons.length) throw new UnsafeDatabaseRoleError(`Refusing to use database role "${s.role}" for tenant data: ${reasons.join("; ")}. Connect with a login role that is only a member of easysign_app.`);
}

export class PostgresLedgerStore<P> implements LedgerStore<P> {
  public readonly kind = "postgres" as const;
  private readonly maxAttempts: number;
  private checked?: Promise<void>;

  constructor(private readonly pool: pg.Pool, private readonly definition: LedgerDefinition<P>, options: { maxAttempts?: number } = {}) {
    this.maxAttempts = options.maxAttempts ?? 8;
  }

  /** Checks the role once (and again after a failure). Called before every operation: the store fails closed. */
  public ready(): Promise<void> {
    if (!this.checked) {
      this.checked = assertSafeApplicationRole(this.pool).catch((e) => { this.checked = undefined; throw e; });
    }
    return this.checked;
  }

  private async inTenant<T>(tenantId: string, work: (client: pg.PoolClient) => Promise<T>): Promise<T> {
    if (typeof tenantId !== "string" || !tenantId) throw new Error("tenantId is required for every ledger operation.");
    await this.ready();
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]); // SET LOCAL app.tenant_id
      const out = await work(client);
      await client.query("COMMIT");
      return out;
    } catch (e) {
      try { await client.query("ROLLBACK"); } catch { /* the connection is already gone */ }
      throw e;
    } finally {
      client.release();
    }
  }

  public async append(tenantId: string, draft: LedgerDraft<P>): Promise<LedgerRecord<P>> {
    const when = new Date(draft.at);
    if (Number.isNaN(when.getTime())) throw new Error("A ledger event needs a valid timestamp.");
    const at = when.toISOString();
    // Hash exactly what a later read will rebuild from jsonb.
    const payload = this.definition.canonical(JSON.parse(JSON.stringify(draft.payload)) as Record<string, unknown>);
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.inTenant(tenantId, async (client) => {
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`easysign.ledger.${this.definition.name}`]);
          const head = await readHead(client, this.definition.name);
          const core = { seq: head.seq + 1, type: draft.type, at, tenantId, payload, prevHash: head.hash };
          const record: LedgerRecord<P> = { ...core, hash: this.definition.hash(core) };
          await client.query(
            "INSERT INTO public.ledger_events (ledger, seq, tenant_id, type, at, payload, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)",
            [this.definition.name, record.seq, tenantId, record.type, at, JSON.stringify(payload), record.prevHash, record.hash],
          );
          return record;
        });
      } catch (e) {
        if (attempt < this.maxAttempts && RETRYABLE.has((e as { code?: string }).code ?? "")) continue;
        throw e;
      }
    }
  }

  public async readAll(tenantId: string): Promise<LedgerRecord<P>[]> {
    return this.inTenant(tenantId, async (client) => {
      const rows = await client.query<EventRow>(
        "SELECT seq, tenant_id, type, at, payload, prev_hash, hash FROM public.ledger_events WHERE ledger = $1 AND tenant_id = $2 ORDER BY seq",
        [this.definition.name, tenantId],
      );
      const head = await readHead(client, this.definition.name);
      const records = rows.rows.map((row) => toRecord(this.definition, row));
      assertChain(this.definition, records, false);
      const foreign = records.find((r) => r.tenantId !== tenantId);
      if (foreign) throw new LedgerChainError(this.definition.name, foreign.seq, `Event ${foreign.seq} belongs to another tenant: row level security is not in effect.`);
      const last = records[records.length - 1];
      if (last && (last.seq > head.seq || (last.seq === head.seq && last.hash !== head.hash))) {
        throw new LedgerChainError(this.definition.name, last.seq, `Event ${last.seq} of ledger "${this.definition.name}" does not match the ledger head.`);
      }
      return records;
    });
  }

  public async verify(tenantId?: string): Promise<boolean> {
    if (!tenantId) throw new Error("The application role only sees one tenant at a time: pass a tenantId, or verify the whole chain with verifyFullChain under the easysign_auditor role.");
    try { await this.readAll(tenantId); return true; } catch (e) { if (e instanceof LedgerChainError) return false; throw e; }
  }
}

/**
 * Verifies a whole ledger (every tenant, every link, and the head). Needs a connection whose role is a member of
 * `easysign_auditor`; under the application role it fails, because that role cannot see the whole chain.
 */
export async function verifyFullChain<P>(db: Queryable, definition: LedgerDefinition<P>): Promise<{ ledger: string; events: number; headHash: string }> {
  const rows = await db.query<EventRow>("SELECT seq, tenant_id, type, at, payload, prev_hash, hash FROM public.ledger_events WHERE ledger = $1 ORDER BY seq", [definition.name]);
  const head = await readHead(db, definition.name);
  const records = rows.rows.map((row) => toRecord(definition, row));
  assertChain(definition, records, true);
  const last = records[records.length - 1];
  if (records.length !== head.seq || (last?.hash ?? GENESIS) !== head.hash) {
    throw new LedgerChainError(definition.name, head.seq, `Ledger "${definition.name}" has ${records.length} visible events but its head is at ${head.seq}: events are missing or this role cannot see the whole chain.`);
  }
  return { ledger: definition.name, events: records.length, headHash: head.hash };
}
