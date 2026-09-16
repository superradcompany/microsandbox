#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The release gate must build before publishing anything. Omit only our native
// packages while installing locked build tools, then restore the exact manifests
// before packing the candidate SDK, even when installation or compilation fails.
export function buildUnpublishedSdk(directory, run = execFileSync) {
  const paths = ["package.json", "package-lock.json"].map((name) => resolve(directory, name));
  const originals = paths.map((path) => readFileSync(path));
  const options = { cwd: directory, stdio: "inherit" };
  try {
    execFileSync(process.execPath, ["scripts/prune-platform-optional-deps.mjs"], options);
    run("npm", ["ci"], options);
    run("npm", ["run", "build:ts"], options);
  } finally {
    paths.forEach((path, index) => writeFileSync(path, originals[index]));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildUnpublishedSdk(resolve(fileURLToPath(new URL("../../sdk/node-ts", import.meta.url))));
}
