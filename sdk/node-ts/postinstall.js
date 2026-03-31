#!/usr/bin/env node

// Downloads msb + libkrunfw binaries to ~/.microsandbox/{bin,lib}/ during npm install.

const { execFileSync, execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const http = require("http");

const PREBUILT_VERSION = require("./package.json").version;
const LIBKRUNFW_ABI = "5";
const LIBKRUNFW_VERSION = "5.2.1";
const GITHUB_ORG = "superradcompany";
const REPO = "microsandbox";
const BASE_DIR = path.join(os.homedir(), ".microsandbox");
const BIN_DIR = path.join(BASE_DIR, "bin");
const LIB_DIR = path.join(BASE_DIR, "lib");

function getArch() {
  const arch = process.arch;
  if (arch === "arm64" || arch === "aarch64") return "aarch64";
  if (arch === "x64" || arch === "x86_64") return "x86_64";
  throw new Error(`Unsupported architecture: ${arch}`);
}

function getOS() {
  const platform = process.platform;
  if (platform === "darwin") return "darwin";
  if (platform === "linux") return "linux";
  throw new Error(`Unsupported platform: ${platform}`);
}

function libkrunfwFilename(targetOS) {
  if (targetOS === "darwin") return `libkrunfw.${LIBKRUNFW_ABI}.dylib`;
  return `libkrunfw.so.${LIBKRUNFW_VERSION}`;
}

function libkrunfwSymlinks(filename, targetOS) {
  if (targetOS === "darwin") {
    return [["libkrunfw.dylib", filename]];
  }
  const soname = `libkrunfw.so.${LIBKRUNFW_ABI}`;
  return [
    [soname, filename],
    ["libkrunfw.so", soname],
  ];
}

function bundleUrl(version, arch, targetOS) {
  return `https://github.com/${GITHUB_ORG}/${REPO}/releases/download/v${version}/${REPO}-${targetOS}-${arch}.tar.gz`;
}

/** Follow redirects and return the response body as a Buffer. */
function download(url) {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https:") ? https.get : http.get;
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

/** Extract a .tar.gz buffer, routing files to bin/ or lib/. */
function extractBundle(data) {
  // Use tar CLI since Node doesn't have built-in tar support without dependencies.
  const tmpFile = path.join(os.tmpdir(), `microsandbox-bundle-${Date.now()}.tar.gz`);
  const tmpExtract = path.join(os.tmpdir(), `microsandbox-extract-${Date.now()}`);

  try {
    fs.writeFileSync(tmpFile, data);
    fs.mkdirSync(tmpExtract, { recursive: true });
    execSync(`tar xzf "${tmpFile}" -C "${tmpExtract}"`, { stdio: "pipe" });

    for (const name of fs.readdirSync(tmpExtract)) {
      const src = path.join(tmpExtract, name);
      const dest = name.startsWith("libkrunfw")
        ? path.join(LIB_DIR, name)
        : path.join(BIN_DIR, name);
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o755);
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
    try { fs.rmSync(tmpExtract, { recursive: true }); } catch {}
  }
}

async function main() {
  const targetOS = getOS();
  const arch = getArch();
  const libkrunfw = libkrunfwFilename(targetOS);

  // Skip if already installed and the bundled msb version matches the
  // current package version.
  if (
    fs.existsSync(path.join(LIB_DIR, libkrunfw)) &&
    installedMsbVersion(path.join(BIN_DIR, "msb")) === PREBUILT_VERSION
  ) {
    return;
  }

  fs.mkdirSync(BIN_DIR, { recursive: true });
  fs.mkdirSync(LIB_DIR, { recursive: true });

  if (installCiLocalBundle(libkrunfw)) {
    console.log("microsandbox: installed runtime dependencies from local CI build/");
    return;
  }

  const url = bundleUrl(PREBUILT_VERSION, arch, targetOS);
  console.log(`microsandbox: downloading runtime dependencies (v${PREBUILT_VERSION})...`);
  const data = await download(url);

  extractBundle(data);

  // Create libkrunfw symlinks.
  for (const [linkName, target] of libkrunfwSymlinks(libkrunfw, targetOS)) {
    const linkPath = path.join(LIB_DIR, linkName);
    try { fs.unlinkSync(linkPath); } catch {}
    fs.symlinkSync(target, linkPath);
  }

  // Verify.
  if (!fs.existsSync(path.join(BIN_DIR, "msb"))) {
    throw new Error("msb binary not found after extraction");
  }
  if (!fs.existsSync(path.join(LIB_DIR, libkrunfw))) {
    throw new Error(`${libkrunfw} not found after extraction`);
  }

  console.log("microsandbox: runtime dependencies installed.");
}

function installedMsbVersion(msbPath) {
  if (!fs.existsSync(msbPath)) {
    return null;
  }

  try {
    const stdout = execFileSync(msbPath, ["--version"], { encoding: "utf8" }).trim();
    return stdout.startsWith("msb ") ? stdout.slice(4) : null;
  } catch {
    return null;
  }
}

function installCiLocalBundle(libkrunfw) {
  if (!process.env.CI) {
    return false;
  }

  const repoRoot = path.resolve(__dirname, "..", "..");
  const buildDir = path.join(repoRoot, "build");
  if (!fs.existsSync(path.join(repoRoot, "Cargo.toml"))) {
    return false;
  }

  const msbSrc = path.join(buildDir, "msb");
  const libSrc = path.join(buildDir, libkrunfw);
  if (!fs.existsSync(msbSrc) || !fs.existsSync(libSrc)) {
    return false;
  }

  fs.copyFileSync(msbSrc, path.join(BIN_DIR, "msb"));
  fs.copyFileSync(libSrc, path.join(LIB_DIR, libkrunfw));
  fs.chmodSync(path.join(BIN_DIR, "msb"), 0o755);
  fs.chmodSync(path.join(LIB_DIR, libkrunfw), 0o755);

  for (const [linkName, target] of libkrunfwSymlinks(libkrunfw, getOS())) {
    const linkPath = path.join(LIB_DIR, linkName);
    try { fs.unlinkSync(linkPath); } catch {}
    fs.symlinkSync(target, linkPath);
  }

  return true;
}

main().catch((err) => {
  console.error(`microsandbox: failed to install runtime dependencies: ${err.message}`);
  console.error("You can install them manually: curl -fsSL https://install.microsandbox.dev | sh");
  // Don't fail the npm install — the user can install manually.
  process.exit(0);
});
