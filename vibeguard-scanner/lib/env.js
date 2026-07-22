// Zero-dependency .env loader.
//
// BYO-key users configure their LLM provider once in a .env file next to the
// scanner instead of exporting variables into every shell. Node 20.12+/22 ships
// process.loadEnvFile natively, so this needs no package. Existing environment
// variables always win over the file, and a missing/broken .env is never fatal.

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scannerRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// Look next to the scanner first, then in the current working directory.
const candidates = [
  path.join(scannerRoot, ".env"),
  path.join(process.cwd(), ".env"),
];

for (const file of candidates) {
  if (!existsSync(file)) continue;
  try {
    process.loadEnvFile(file);
  } catch {
    // Older Node without loadEnvFile, or a malformed file: ignore and rely on
    // real environment variables. The scan still runs (AI pass just skips if no key).
  }
  break;
}
