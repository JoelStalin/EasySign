import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type pg from "pg";

/**
 * Small versioned migration runner. Files are `migrations/NNN_name.sql`, applied in order, each in its own
 * transaction, and recorded in `schema_migrations` with a SHA-256 of the file. A migration that was already applied
 * must never change: a different checksum stops the run.
 */

export interface Migration { version: number; name: string; sql: string; checksum: string }

export const DEFAULT_MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations", import.meta.url));
const FILE = /^(\d+)_([a-z0-9_]+)\.sql$/;

export function loadMigrations(dir: string = DEFAULT_MIGRATIONS_DIR): Migration[] {
  const found = readdirSync(dir).filter((f) => f.endsWith(".sql")).map((file) => {
    const m = FILE.exec(file);
    if (!m) throw new Error(`Migration file "${file}" must be named NNN_name.sql (lowercase letters, digits and underscores).`);
    const sql = readFileSync(join(dir, file), "utf8");
    return { version: Number(m[1]), name: m[2], sql, checksum: createHash("sha256").update(sql, "utf8").digest("hex") };
  }).sort((a, b) => a.version - b.version);
  found.forEach((m, i) => {
    if (m.version !== i + 1) throw new Error(`Migrations must be numbered 1..n without gaps or duplicates; found version ${m.version} at position ${i + 1}.`);
  });
  return found;
}

/** Applies what is pending and returns the versions it applied. Takes one dedicated connection (not a pool). */
export async function runMigrations(client: pg.ClientBase, dir: string = DEFAULT_MIGRATIONS_DIR): Promise<number[]> {
  const migrations = loadMigrations(dir);
  await client.query("SELECT pg_advisory_lock(hashtextextended('easysign.migrations', 0))");
  try {
    await client.query("CREATE TABLE IF NOT EXISTS public.schema_migrations (version integer PRIMARY KEY, name text NOT NULL, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())");
    const done = new Map((await client.query<{ version: number; checksum: string }>("SELECT version, checksum FROM public.schema_migrations")).rows.map((r) => [r.version, r.checksum]));
    const unknown = [...done.keys()].find((v) => v > migrations.length);
    if (unknown) throw new Error(`The database is at migration ${unknown}, which this build does not have: deploy a newer build.`);
    const applied: number[] = [];
    for (const m of migrations) {
      const known = done.get(m.version);
      if (known) {
        if (known !== m.checksum) throw new Error(`Migration ${m.version}_${m.name} was changed after it was applied (checksum mismatch). Write a new migration instead.`);
        continue;
      }
      await client.query("BEGIN");
      try {
        await client.query(m.sql);
        await client.query("INSERT INTO public.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", [m.version, m.name, m.checksum]);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${m.version}_${m.name} failed and was rolled back: ${(e as Error).message}`, { cause: e });
      }
      applied.push(m.version);
    }
    return applied;
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtextextended('easysign.migrations', 0))");
  }
}
