#!/usr/bin/env node

import { execFileSync } from "node:child_process";

const [version, ...packages] = process.argv.slice(2);
if (!version || packages.length === 0) {
  console.error("usage: wait-for-npm-packages.mjs <version> <package>...");
  process.exit(2);
}

const timeoutMs = Number(process.env.NPM_INDEX_TIMEOUT_MS ?? 180_000);
const deadline = Date.now() + timeoutMs;
let delayMs = 1_000;
let pending = [...packages];

while (pending.length > 0) {
  // Registry propagation varies widely; query the exact version instead of
  // paying a fixed sleep on fast runs or racing the registry on slow ones.
  pending = pending.filter((name) => {
    try {
      const found = execFileSync(
        "npm",
        ["view", `${name}@${version}`, "version", "--json"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
      );
      return JSON.parse(found) !== version;
    } catch {
      return true;
    }
  });

  if (pending.length === 0) break;
  if (Date.now() >= deadline) {
    throw new Error(`timed out waiting for npm: ${pending.join(", ")}`);
  }

  console.log(`waiting ${delayMs / 1000}s for npm: ${pending.join(", ")}`);
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  delayMs = Math.min(delayMs * 2, 20_000);
}

console.log(`npm packages visible at ${version}: ${packages.join(", ")}`);
