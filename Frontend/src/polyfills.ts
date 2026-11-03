/**
 * Node globals the Solana libraries expect, provided before anything imports
 * them.
 *
 * `@solana/web3.js` and `@solana/spl-token` were written for Node and reach for
 * the `Buffer` global at module scope — not inside a function, at import time.
 * A browser has no such global, and Vite does not polyfill it: it externalises
 * the `buffer` module and warns, so the first import of spl-token throws
 * `ReferenceError: Buffer is not defined` and React never mounts. The symptom
 * is a blank page on *every* route, because the crash happens while the module
 * graph is still loading.
 *
 * Neither `tsc` nor `vite build` catches this. Both are happy: the types are
 * real and the bundle is valid. It only fails when the code runs, which is why
 * it survived until someone opened the page.
 *
 * This must be the **first** import in `main.tsx`. ES modules are evaluated in
 * import order, so a polyfill placed after the import that needs it runs too
 * late to help.
 */
import { Buffer } from "buffer";

declare global {
  // eslint-disable-next-line no-var
  var Buffer: typeof import("buffer").Buffer;
}

// Assigned rather than replaced: a browser that somehow already has one, or a
// test environment that provides its own, keeps it.
globalThis.Buffer = globalThis.Buffer ?? Buffer;
