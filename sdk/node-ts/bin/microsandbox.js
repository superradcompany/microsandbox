#!/usr/bin/env node

// Thin shim that forwards all arguments to the installed msb binary.
// Self-heals if msb is missing (e.g. stale npx cache, skipped postinstall):
// downloads the runtime on first run, then exec.

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { ensureMsb } = require("../lib/install");

function resolveMsb() {
  if (process.env.MSB_PATH) return { path: process.env.MSB_PATH, fromEnv: true };
  const home = os.homedir();
  if (!home) return null;
  return { path: path.join(home, ".microsandbox", "bin", "msb"), fromEnv: false };
}

async function main() {
  const resolved = resolveMsb();
  if (!resolved) {
    console.error("microsandbox: could not determine home directory");
    process.exit(127);
  }

  let msb = resolved.path;
  if (!fs.existsSync(msb)) {
    if (resolved.fromEnv) {
      console.error(`microsandbox: MSB_PATH points at nonexistent ${msb}`);
      process.exit(127);
    }
    try {
      msb = await ensureMsb({ ephemeralStatus: true });
    } catch (err) {
      console.error(`microsandbox: failed to download runtime: ${err.message}`);
      console.error("microsandbox: retry, or set MSB_PATH to an existing msb binary.");
      process.exit(127);
    }
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
}

main();
