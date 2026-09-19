#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const directory = resolve(process.argv[2] ?? ".");
const pkg = JSON.parse(readFileSync(resolve(directory, "package.json"), "utf8"));
const url = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/${pkg.version}`;
const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
if (response.ok) {
  const published = await response.json();
  if (published.name !== pkg.name || published.version !== pkg.version) {
    throw new Error(`Unexpected registry metadata for ${pkg.name}@${pkg.version}`);
  }
  console.log(`Already published: ${pkg.name}@${pkg.version}`);
} else if (response.status === 404) {
  execFileSync("npm", ["publish", "--access", "public"], {
    cwd: directory,
    stdio: "inherit",
  });
} else {
  throw new Error(`Registry lookup failed: HTTP ${response.status} for ${pkg.name}@${pkg.version}`);
}
