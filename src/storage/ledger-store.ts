import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Storage for the append-only, SHA-256 hash-chained ledgers (backlog ES-006).
 * A store holds one ledger. The ledger keeps a single chain across tenants (seq 1..n, each event carries the hash of
 * the previous one); reads are always scoped to one tenant.
 */

export const GENESIS = "0".repeat(64);

export interface LedgerRecord<P> {
  seq: number;
  type: string;
  /** ISO-8601 UTC with milliseconds, exactly as hashed. */
  at: string;
  tenantId: string;
  payload: P;
  prevHash: string;
  hash: string;
}

export interface LedgerDraft<P> {
  type: string;
  at: string;
  payload: P;
}

/** What makes a ledger: its name and how its events are hashed. */
export interface LedgerDefinition<P> {
  /** Lowercase identifier, also the value of the `ledger` column. */
  name: string;
  /** For ledgers whose events have no type of their own: JSONL lines omit the type and it is filled in on load. */
  fixedType?: string;
  hash(record: Omit<LedgerRecord<P>, "hash">): string;
  /**
   * Rebuilds a payload with its keys in the order the hash expects. PostgreSQL `jsonb` does not keep key order,
   * so anything hashed through JSON.stringify must be re-ordered after a round trip.
   */
  canonical(payload: Record<string, unknown>): P;
}

export class LedgerChainError extends Error {
  constructor(public readonly ledger: string, public readonly seq: number, message: string) {
    super(message);
    this.name = "LedgerChainError";
  }
}

export interface LedgerStore<P> {
  readonly kind: "memory" | "file" | "postgres";
  /** Appends one event for the tenant and returns it with its sequence number and hashes. */
  append(tenantId: string, draft: LedgerDraft<P>): Promise<LedgerRecord<P>>;
  /** Every event of that tenant, oldest first, verified against the hash chain. Throws LedgerChainError if altered. */
  readAll(tenantId: string): Promise<LedgerRecord<P>[]>;
  /**
   * With a tenant: verifies what that tenant can see. Without: verifies the whole chain, which the PostgreSQL store
   * cannot do under the application role (use `verifyFullChain` with the auditor role).
   */
  verify(tenantId?: string): Promise<boolean>;
  /** Sequence number and hash of the last event of the whole ledger (0 and the genesis hash when empty). */
  head(): Promise<{ seq: number; hash: string }>;
  /** Every event of every tenant. Only stores that hold the whole chain have it; the PostgreSQL store does not. */
  readEverything?(): Promise<LedgerRecord<P>[]>;
}

/**
 * Checks records against the chain. `complete` means the records are the whole ledger (seq 1..n, every link checked).
 * Otherwise they are one tenant's view: hashes are recomputed, sequence numbers must increase, and links are checked
 * wherever two consecutive events are both visible.
 */
export function assertChain<P>(definition: LedgerDefinition<P>, records: readonly LedgerRecord<P>[], complete: boolean): void {
  const broken = (r: LedgerRecord<P>) => new LedgerChainError(definition.name, r.seq, `Event ${r.seq} of ledger "${definition.name}" does not match the hash chain: the ledger was altered.`);
  let prev: LedgerRecord<P> | undefined;
  records.forEach((r, i) => {
    const { hash, ...core } = r;
    if (hash !== definition.hash(core)) throw broken(r);
    if (complete) {
      if (r.seq !== i + 1 || r.prevHash !== (prev?.hash ?? GENESIS)) throw broken(r);
    } else {
      if (!Number.isSafeInteger(r.seq) || r.seq <= (prev?.seq ?? 0)) throw broken(r);
      if (r.seq === 1 && r.prevHash !== GENESIS) throw broken(r);
      if (prev && r.seq === prev.seq + 1 && r.prevHash !== prev.hash) throw broken(r);
    }
    prev = r;
  });
}

const RESERVED = new Set(["seq", "type", "at", "tenantId", "prevHash", "hash"]);

/**
 * The original behaviour: events live in memory and, when `filePath` is given, in a JSONL file that is read and
 * verified when the store is created (it throws LedgerChainError if the file was altered). Each line is the flat
 * event (`seq,type,at,tenantId,...payload,prevHash,hash`), so files written before LedgerStore existed still load.
 */
export class FileLedgerStore<P extends object> implements LedgerStore<P> {
  public readonly kind: "memory" | "file";
  private readonly records: LedgerRecord<P>[] = [];
  private readonly filePath?: string;

  constructor(private readonly definition: LedgerDefinition<P>, options: { filePath?: string } = {}) {
    this.filePath = options.filePath;
    this.kind = this.filePath ? "file" : "memory";
    if (!this.filePath) return;
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    if (!existsSync(this.filePath)) return;
    for (const line of readFileSync(this.filePath, "utf8").split("\n").filter(Boolean)) {
      const { seq, type, at, tenantId, prevHash, hash, ...payload } = JSON.parse(line) as Record<string, unknown>;
      this.records.push({ seq, type: type ?? this.definition.fixedType, at, tenantId, payload, prevHash, hash } as LedgerRecord<P>);
    }
    assertChain(this.definition, this.records, true);
  }

  public async append(tenantId: string, draft: LedgerDraft<P>): Promise<LedgerRecord<P>> {
    if (!tenantId) throw new Error("tenantId is required to append to a ledger.");
    const clash = Object.keys(draft.payload).find((k) => RESERVED.has(k));
    if (clash) throw new Error(`Payload key "${clash}" is reserved by the ledger envelope.`);
    const prev = this.records[this.records.length - 1];
    const core = { seq: this.records.length + 1, type: draft.type, at: draft.at, tenantId, payload: draft.payload, prevHash: prev?.hash ?? GENESIS };
    const record: LedgerRecord<P> = { ...core, hash: this.definition.hash(core) };
    if (this.filePath) {
      const { payload, prevHash, hash, type, ...head } = record;
      const envelope = this.definition.fixedType ? head : { seq: head.seq, type, at: head.at, tenantId: head.tenantId };
      appendFileSync(this.filePath, JSON.stringify({ ...envelope, ...payload, prevHash, hash }) + "\n");
    }
    this.records.push(record);
    return record;
  }

  public async readAll(tenantId: string): Promise<LedgerRecord<P>[]> {
    return this.records.filter((r) => r.tenantId === tenantId);
  }

  public async readEverything(): Promise<LedgerRecord<P>[]> {
    return [...this.records];
  }

  public async head(): Promise<{ seq: number; hash: string }> {
    const last = this.records[this.records.length - 1];
    return { seq: last?.seq ?? 0, hash: last?.hash ?? GENESIS };
  }

  /** The file store always holds the whole chain, so it verifies all of it whatever the tenant. */
  public async verify(_tenantId?: string): Promise<boolean> {
    try { assertChain(this.definition, this.records, true); return true; } catch { return false; }
  }
}
