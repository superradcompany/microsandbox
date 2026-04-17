#!/usr/bin/env node

// Thin shim that forwards all arguments to the installed msb binary.
//
// Resolution order:
//   1. MSB_PATH environment variable
//   2. ~/.microsandbox/bin/msb (populated by postinstall.js)

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

function resolveMsb() {
  if (process.env.MSB_PATH) return process.env.MSB_PATH;
  const home = os.homedir();
  if (!home) return null;
  const p = path.join(home, ".microsandbox", "bin", "msb");
  return fs.existsSync(p) ? p : null;
}

const msb = resolveMsb();
if (!msb) {
  console.error(
    "microsandbox: msb binary not found. Set MSB_PATH or ensure ~/.microsandbox/bin/msb exists."
  );
  process.exit(127);
}

const result = spawnSync(msb, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`microsandbox: failed to run ${msb}: ${result.error.message}`);
  process.exit(127);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
  process.exit(1);
}
process.exit(result.status ?? 0);
