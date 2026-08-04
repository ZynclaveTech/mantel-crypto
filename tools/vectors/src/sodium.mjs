// Single import point for libsodium.
//
// WHY THIS FILE EXISTS: libsodium-wrappers-sumo@0.7.16 ships a BROKEN ESM
// build. Its package.json `exports.import` points at
//   dist/modules-sumo-esm/libsodium-wrappers.mjs
// which does `import ... from "./libsodium-sumo.mjs"` — a file the published
// npm tarball does not contain. So a plain `import _sodium from
// "libsodium-wrappers-sumo"` fails with ERR_MODULE_NOT_FOUND on any fresh
// install.
//
// The CommonJS build (dist/modules-sumo/libsodium-wrappers.js) IS shipped and
// is intact, so we load that via createRequire. This is a real fix, not a
// workaround: it lives in tracked source and survives `npm ci`, unlike
// patching anything under node_modules.
//
// Every module and test in this package MUST import sodium from here rather
// than from the package directly, so the fix stays in one place. If a future
// version of libsodium-wrappers-sumo ships a working ESM build, this file is
// the only thing that changes.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const _sodium = require("libsodium-wrappers-sumo");

/**
 * Returns the initialised libsodium instance.
 *
 * libsodium compiles from WASM asynchronously, so `_sodium.ready` must be
 * awaited before any primitive is called — calling one earlier throws an
 * unhelpful error about missing exports.
 */
export async function loadSodium() {
  await _sodium.ready;
  return _sodium;
}
