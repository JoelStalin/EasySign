import { documentStoreFromEnv } from "../services/document-store.js";

/**
 * Brings every stored document under the current key: `npm run docs:reencrypt` (after `npm run build`).
 * Needs EASYSIGN_DOCS_DIR, EASYSIGN_DOCS_KEK, EASYSIGN_DOCS_KEK_ID and, when rotating, EASYSIGN_DOCS_KEK_PREVIOUS.
 * Prints a JSON report; exits with 1 if any file could not be processed. See docs/ENCRYPTION_AT_REST.md.
 */
try {
  const report = documentStoreFromEnv(process.env).reencryptAll();
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.failed.length ? 1 : 0;
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exitCode = 2;
}
