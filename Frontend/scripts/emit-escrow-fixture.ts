/**
 * Write the escrow fixture the Anchor suite checks against.
 *
 *     cd Frontend && npx vite-node scripts/emit-escrow-fixture.ts
 *
 * Separate from the builder so that importing the fixture -- which the browser's
 * own test does, to prove the committed copy is current -- never writes a file
 * as a side effect of being imported.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildFixture } from "./escrow-fixture";

const FIXTURE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../contracts/solana/tests/fixtures/browser-create-order.json",
);

mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
writeFileSync(FIXTURE_PATH, `${JSON.stringify(buildFixture(), null, 2)}\n`, "utf8");
console.log(`wrote ${FIXTURE_PATH}`);
