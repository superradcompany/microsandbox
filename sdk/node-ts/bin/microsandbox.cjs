#!/usr/bin/env node

// Thin shim that forwards all arguments to the bundled msb binary.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const TRIPLES = {
  "darwin-arm64": "darwin-arm64",
  "linux-x64": "linux-x64-gnu",
  "linux-arm64": "linux-arm64-gnu",
};

function resolveMsb() {
  if (process.env.MSB_PATH) {
    return { path: process.env.MSB_PATH, source: "MSB_PATH" };
  }

  const triple = TRIPLES[`${process.platform}-${process.arch}`];
  if (triple) {
    try {
      const pkgPath = require.resolve(
        `@superradcompany/microsandbox-${triple}/package.json`,
      );
      const candidate = path.join(path.dirname(pkgPath), "bin", "msb");
      if (fs.existsSync(candidate)) {
        return { path: candidate, source: "platform-package" };
      }
    } catch {
      // platform package not installed - fall through
    }
  }

  return null;
}

const resolved = resolveMsb();
if (!resolved) {
  console.error(
    "microsandbox: msb binary not found. Reinstall the package " +
      "(npm i -g microsandbox) or set MSB_PATH to a working binary.",
  );
  process.exit(127);
}

const result = spawnSync(resolved.path, process.argv.slice(2), {
  stdio: "inherit",
});

if (result.error) {
  console.error(
    `microsandbox: failed to run ${resolved.path}: ${result.error.message}`,
  );
  process.exit(127);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
  process.exit(1);
}
process.exit(result.status ?? 0);
