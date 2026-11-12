import pg from "pg";
import { CONSENT_LEDGER } from "../services/consent-ledger.js";
import { runMigrations } from "./migrate.js";
import { verifyFullChain } from "./postgres-ledger-store.js";

/**
 * Operator commands (see docs/POSTGRES_TENANCY.md):
 *   node dist/storage/cli.js migrate   uses EASYSIGN_MIGRATION_DATABASE_URL (schema owner)
 *   node dist/storage/cli.js verify    uses EASYSIGN_AUDIT_DATABASE_URL (member of easysign_auditor)
 * Neither uses the application URL: the API role cannot change the schema nor read every tenant.
 */
const LEDGERS = [CONSENT_LEDGER];

async function main(): Promise<void> {
  const command = process.argv[2];
  const variable = command === "migrate" ? "EASYSIGN_MIGRATION_DATABASE_URL" : command === "verify" ? "EASYSIGN_AUDIT_DATABASE_URL" : undefined;
  if (!variable) throw new Error("Usage: node dist/storage/cli.js <migrate|verify>");
  const connectionString = process.env[variable];
  if (!connectionString) throw new Error(`${variable} is not set.`);
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    if (command === "migrate") {
      const applied = await runMigrations(client);
      console.log(applied.length ? `Applied migrations: ${applied.join(", ")}` : "Nothing to apply: the schema is up to date.");
    } else {
      for (const ledger of LEDGERS) {
        const r = await verifyFullChain(client, ledger);
        console.log(`Ledger "${r.ledger}": ${r.events} events, chain valid, head ${r.headHash}`);
      }
    }
  } finally {
    await client.end();
  }
}

main().catch((e: unknown) => { console.error((e as Error).message); process.exit(1); });
