#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageJsonPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "package.json",
);

const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
const optionalDependencies = packageJson.optionalDependencies ?? {};
const removed = [];

for (const dependencyName of Object.keys(optionalDependencies)) {
  if (dependencyName.startsWith("@superradcompany/microsandbox-")) {
    delete optionalDependencies[dependencyName];
    removed.push(dependencyName);
  }
}

if (removed.length > 0) {
  packageJson.optionalDependencies = optionalDependencies;
  writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
}

console.log(
  removed.length === 0
    ? "No microsandbox platform optional dependencies to prune."
    : `Pruned microsandbox platform optional dependencies: ${removed.join(", ")}`,
);
