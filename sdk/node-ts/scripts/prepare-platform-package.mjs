#!/usr/bin/env node
// Populate a platform package (npm/<triple>) with the bundled runtime
// for the current host. Intended for both local dev (run after `just build &&
// npm run build:native`) and CI (run on each matrix runner before publish).
//
// Layout produced:
//   npm/<triple>/microsandbox.<triple>.node    (the napi binding)
//   npm/<triple>/bin/msb                        (the msb CLI)
//   npm/<triple>/lib/libkrunfw.{dylib|so}       (the krun shared library)
//
// Refuses to run when the host triple doesn't match the requested target,
// since we don't cross-compile here — CI orchestrates that matrix.

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sdkRoot = resolve(__dirname, "..");
const repoRoot = resolve(sdkRoot, "../..");

function detectHostTriple() {
  const p = process.platform;
  const a = process.arch;
  if (p === "darwin" && a === "arm64") return "darwin-arm64";
  if (p === "linux" && a === "x64") return "linux-x64-gnu";
  if (p === "linux" && a === "arm64") return "linux-arm64-gnu";
  throw new Error(`unsupported host: ${p}-${a}`);
}

const triple = process.argv[2] ?? detectHostTriple();
if (!["darwin-arm64", "linux-x64-gnu", "linux-arm64-gnu"].includes(triple)) {
  console.error(`unknown triple: ${triple}`);
  process.exit(2);
}
if (triple !== detectHostTriple()) {
  console.error(
    `cannot prepare ${triple} on host ${detectHostTriple()} — cross-compile in CI instead.`,
  );
  process.exit(2);
}

const pkgDir = join(sdkRoot, "npm", triple);
const binDir = join(pkgDir, "bin");
const libDir = join(pkgDir, "lib");
mkdirSync(binDir, { recursive: true });
mkdirSync(libDir, { recursive: true });

// 1. napi binding ---------------------------------------------------------
const nodeFile = `microsandbox.${triple}.node`;
const builtNode = join(sdkRoot, "native", nodeFile);
if (!existsSync(builtNode)) {
  console.error(
    `missing napi binding at ${builtNode} — run \`npm run build:native\` first.`,
  );
  process.exit(1);
}
copyFileSync(builtNode, join(pkgDir, nodeFile));
console.log(`copied ${nodeFile}`);

// 2. msb binary -----------------------------------------------------------
// Prefer the just-built msb in build/msb (signed). Fall back to target/release.
const msbCandidates = [
  join(repoRoot, "build", "msb"),
  join(repoRoot, "target", "release", "microsandbox"),
];
const msbSrc = msbCandidates.find((p) => existsSync(p));
if (!msbSrc) {
  console.error(
    `missing msb binary; run \`just build\` from the repo root first.\n` +
      `looked in:\n` +
      msbCandidates.map((p) => `  ${p}`).join("\n"),
  );
  process.exit(1);
}
const msbDst = join(binDir, "msb");
copyFileSync(msbSrc, msbDst);
execFileSync("chmod", ["+x", msbDst]);
console.log(`copied msb (${msbSrc})`);

// On macOS, codesign the bundled binary with the hypervisor entitlement
// so Hypervisor.framework will accept it.
if (triple === "darwin-arm64") {
  const entitlements = join(repoRoot, "msb-entitlements.plist");
  if (!existsSync(entitlements)) {
    console.error(`missing ${entitlements}; cannot codesign.`);
    process.exit(1);
  }
  execFileSync(
    "codesign",
    ["--entitlements", entitlements, "--force", "-s", "-", msbDst],
    { stdio: "inherit" },
  );
  console.log(`codesigned msb`);
}

// 3. libkrunfw shared library --------------------------------------------
// `just build` lands these in build/. Match the {dylib,so} filename for the host.
const libExt = process.platform === "darwin" ? "dylib" : "so";
const buildDir = join(repoRoot, "build");
let krunfw;
let krunfwVersioned; // e.g. libkrunfw.5.dylib or libkrunfw.so.5
if (existsSync(buildDir)) {
  const entries = readdirSync(buildDir);
  // Pick the highest-versioned libkrunfw
  const real = entries
    .filter((e) =>
      process.platform === "darwin"
        ? /^libkrunfw\.\d+\.dylib$/.test(e)
        : /^libkrunfw\.so\.\d+$/.test(e),
    )
    .sort()
    .reverse()[0];
  if (real) {
    krunfwVersioned = real;
    krunfw = process.platform === "darwin" ? "libkrunfw.dylib" : "libkrunfw.so";
  }
}
if (!krunfwVersioned) {
  console.error(
    `missing libkrunfw in ${buildDir}; run \`just build-libkrunfw\` first.`,
  );
  process.exit(1);
}

// Copy the versioned dylib AND a duplicate under the unversioned name.
// We can't ship a symlink because `npm pack` doesn't preserve them.
copyFileSync(join(buildDir, krunfwVersioned), join(libDir, krunfwVersioned));
const unversionedPath = join(libDir, krunfw);
if (existsSync(unversionedPath)) unlinkSync(unversionedPath);
copyFileSync(join(buildDir, krunfwVersioned), unversionedPath);
console.log(`copied ${krunfwVersioned} + ${krunfw} (duplicate)`);

// 4. Summary --------------------------------------------------------------
function du(p) {
  return Math.round(statSync(p).size / 1024);
}
console.log(`\npopulated npm/${triple}:`);
console.log(`  ${nodeFile}     ${du(join(pkgDir, nodeFile))} KiB`);
console.log(`  bin/msb         ${du(msbDst)} KiB`);
console.log(`  lib/${krunfwVersioned}  ${du(join(libDir, krunfwVersioned))} KiB`);
