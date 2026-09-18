#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = join(dirname(fileURLToPath(import.meta.url)), "..");
const packageJsonPath = join(packageDirectory, "package.json");
const packageLockPath = join(packageDirectory, "package-lock.json");

const isPlatformDependency = (dependencyName) =>
  dependencyName.startsWith("@superradcompany/microsandbox-");

const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
const optionalDependencies = packageJson.optionalDependencies ?? {};
const removed = [];

for (const dependencyName of Object.keys(optionalDependencies)) {
  if (isPlatformDependency(dependencyName)) {
    delete optionalDependencies[dependencyName];
    removed.push(dependencyName);
  }
}

if (removed.length > 0) {
  if (Object.keys(optionalDependencies).length === 0) {
    delete packageJson.optionalDependencies;
  } else {
    packageJson.optionalDependencies = optionalDependencies;
  }
  writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);

  // Keep the lockfile consistent so CI can use `npm ci` instead of resolving a fresh dependency
  // graph. npm 10 can crash in its peer resolver when the floating graph changes underneath this
  // package, while the checked-in lockfile is deterministic and already reviewed.
  const packageLock = JSON.parse(readFileSync(packageLockPath, "utf8"));
  const lockedRootDependencies = packageLock.packages?.[""]?.optionalDependencies;
  if (lockedRootDependencies) {
    for (const dependencyName of Object.keys(lockedRootDependencies)) {
      if (isPlatformDependency(dependencyName)) {
        delete lockedRootDependencies[dependencyName];
      }
    }
    if (Object.keys(lockedRootDependencies).length === 0) {
      delete packageLock.packages[""].optionalDependencies;
    }
  }
  for (const dependencyName of removed) {
    delete packageLock.packages[`node_modules/${dependencyName}`];
  }
  writeFileSync(packageLockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
}

console.log(
  removed.length === 0
    ? "No microsandbox platform optional dependencies to prune."
    : `Pruned microsandbox platform optional dependencies: ${removed.join(", ")}`,
);
