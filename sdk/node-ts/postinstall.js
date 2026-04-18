#!/usr/bin/env node

// Fast-path: downloads msb + libkrunfw during `npm install`. Not required
// for correctness — the bin shim self-heals if this is skipped (for example
// by `npx` using a cached install). Printing to stderr here also doesn't
// fail the install if the download is unavailable (e.g. new release not yet
// published); the next `microsandbox ...` invocation will retry.

const { ensureMsb } = require("./lib/install");

ensureMsb().catch((err) => {
  console.error(`microsandbox: runtime install deferred: ${err.message}`);
  console.error("microsandbox: will download on first run of the CLI.");
  // Don't fail the npm install — the shim will recover on first invocation.
  process.exit(0);
});
