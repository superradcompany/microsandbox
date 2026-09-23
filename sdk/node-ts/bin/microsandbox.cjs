#!/usr/bin/env node

// Keep the CLI shim usable without loading a native addon. Its pair lookup
// follows setup::resolve_runtime: explicit paths, resolved home, then package.
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { homedir } = require("node:os");

const TRIPLES = {
  "darwin-arm64": "darwin-arm64",
  "linux-x64": "linux-x64-gnu",
  "linux-arm64": "linux-arm64-gnu",
  "win32-x64": "win32-x64-msvc",
  "win32-arm64": "win32-arm64-msvc",
};

function msbFileName() {
  return process.platform === "win32" ? "msb.exe" : "msb";
}

// These filenames match microsandbox-utils and the platform package layout.
function libraryFileName() {
  if (process.platform === "darwin") return "libkrunfw.5.dylib";
  if (process.platform === "win32") return "libkrunfw.dll";
  return "libkrunfw.so.5.6.1";
}

function isFile(file) {
  try {
    return fs.statSync(file).isFile();
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return false;
    throw error;
  }
}

function requirePair(msb, library, source) {
  const directory = path.dirname(msb);
  library ??= [
    path.join(directory, libraryFileName()),
    path.join(directory, "..", "lib", libraryFileName()),
  ].find(isFile);
  if (!library || !isFile(msb) || !isFile(library)) {
    throw new Error(`incomplete runtime: expected ${msb} and matching libkrunfw`);
  }
  return { path: msb, source };
}

function packagedMsb() {
  const triple = TRIPLES[`${process.platform}-${process.arch}`];
  if (!triple) return null;
  try {
    const pkgPath = require.resolve(
      `@superradcompany/microsandbox-${triple}/package.json`,
    );
    const candidate = path.join(path.dirname(pkgPath), "bin", msbFileName());
    return isFile(candidate) ? candidate : null;
  } catch (error) {
    if (error.code === "MODULE_NOT_FOUND") return null;
    throw error;
  }
}

function resolveMsb(packagePath = packagedMsb) {
  const env = process.env;
  if (env.MSB_LIBKRUNFW_PATH !== undefined && env.MSB_PATH === undefined) {
    throw new Error("MSB_LIBKRUNFW_PATH requires MSB_PATH so the pair is explicit");
  }
  if (env.MSB_PATH !== undefined) {
    return requirePair(env.MSB_PATH, env.MSB_LIBKRUNFW_PATH, "MSB_PATH");
  }

  const defaultHome = env.MSB_HOME || path.join(homedir(), ".microsandbox");
  const configPath = env.MSB_CONFIG_PATH ?? path.join(defaultHome, "config.json");
  const config = fs.existsSync(configPath)
    ? JSON.parse(fs.readFileSync(configPath, "utf8"))
    : {};
  if (config.paths?.msb != null) {
    return requirePair(config.paths.msb, config.paths.libkrunfw, "configuration");
  }
  if (config.paths?.libkrunfw != null) {
    throw new Error("config.paths.libkrunfw requires config.paths.msb");
  }

  const home = config.home ?? defaultHome;
  const msb = path.join(home, "bin", msbFileName());
  const library = path.join(home, "lib", libraryFileName());
  // Either file means home is selected: a broken installation must not be
  // silently bypassed by the packaged copy.
  if (isFile(msb) || isFile(library)) {
    return requirePair(msb, library, "home");
  }
  const candidate = packagePath();
  return candidate ? requirePair(candidate, undefined, "platform-package") : null;
}

function main() {
  let resolved;
  try {
    resolved = resolveMsb();
  } catch (error) {
    console.error(`microsandbox: ${error.message}`);
    process.exitCode = 127;
    return;
  }
  if (!resolved) {
    console.error("microsandbox: runtime not installed; install msb and libkrunfw or reinstall the package.");
    process.exitCode = 127;
    return;
  }
  const result = spawnSync(resolved.path, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) {
    console.error(`microsandbox: failed to run ${resolved.path}: ${result.error.message}`);
    process.exitCode = 127;
    return;
  }
  if (result.signal) {
    process.kill(process.pid, result.signal);
    process.exitCode = 1;
    return;
  }
  process.exitCode = result.status ?? 0;
}

if (require.main === module) main();
module.exports = { resolveMsb };
