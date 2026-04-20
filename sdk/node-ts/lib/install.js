// Shared runtime provisioning for microsandbox.
//
// Downloads msb + libkrunfw into ~/.microsandbox/{bin,lib}/ when the bundled
// binary is missing or the installed version does not match the package
// version. Used by postinstall.js (fast path) and bin/microsandbox.js (self-
// heal fallback).

const { execFileSync, execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const http = require("http");

const PREBUILT_VERSION = require("../package.json").version;
const LIBKRUNFW_ABI = "5";
const LIBKRUNFW_VERSION = "5.2.1";
const GITHUB_ORG = "superradcompany";
const REPO = "microsandbox";
const BASE_DIR = path.join(os.homedir(), ".microsandbox");
const BIN_DIR = path.join(BASE_DIR, "bin");
const LIB_DIR = path.join(BASE_DIR, "lib");
const LOCK_PATH = path.join(BASE_DIR, ".install.lock");

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

function installedMsbVersion(msbPath) {
  if (!fs.existsSync(msbPath)) return null;
  try {
    const stdout = execFileSync(msbPath, ["--version"], { encoding: "utf8" }).trim();
    return stdout.startsWith("msb ") ? stdout.slice(4) : null;
  } catch {
    return null;
  }
}

// Cheap check — does a usable msb matching PREBUILT_VERSION exist?
function isInstalled() {
  const targetOS = getOS();
  const libkrunfw = libkrunfwFilename(targetOS);
  return (
    fs.existsSync(path.join(LIB_DIR, libkrunfw)) &&
    installedMsbVersion(path.join(BIN_DIR, "msb")) === PREBUILT_VERSION
  );
}

function msbPath() {
  return path.join(BIN_DIR, "msb");
}

// Follow redirects and return the response body as a Buffer, streaming
// progress via `onProgress({current, total})` if a Content-Length is known.
function download(url, onProgress) {
  return new Promise((resolve, reject) => {
    const get = url.startsWith("https:") ? https.get : http.get;
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, onProgress).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const total = parseInt(res.headers["content-length"] || "0", 10);
      let current = 0;
      const chunks = [];
      res.on("data", (chunk) => {
        chunks.push(chunk);
        current += chunk.length;
        if (onProgress && total) onProgress({ current, total });
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

function extractBundle(data) {
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
      // Atomic: write to .tmp then rename. Avoids a half-written binary
      // being observable by a concurrent shim that's just looking up existence.
      const tmpDest = `${dest}.tmp-${process.pid}`;
      fs.copyFileSync(src, tmpDest);
      fs.chmodSync(tmpDest, 0o755);
      fs.renameSync(tmpDest, dest);
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
    try { fs.rmSync(tmpExtract, { recursive: true }); } catch {}
  }
}

function installCiLocalBundle(libkrunfw) {
  if (!process.env.CI) return false;

  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  const buildDir = path.join(repoRoot, "build");
  if (!fs.existsSync(path.join(repoRoot, "Cargo.toml"))) return false;

  const msbSrc = path.join(buildDir, "msb");
  const libSrc = path.join(buildDir, libkrunfw);
  if (!fs.existsSync(msbSrc) || !fs.existsSync(libSrc)) return false;

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

// Best-effort file lock: O_EXCL create. If another process holds the lock,
// poll until it releases (max ~5 min) or bail out.
async function withLock(body) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
  const deadline = Date.now() + 5 * 60 * 1000;
  let fd = null;
  while (Date.now() < deadline) {
    try {
      fd = fs.openSync(LOCK_PATH, "wx");
      break;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      // Stale lock? If holder PID is dead, reclaim.
      try {
        const pid = parseInt(fs.readFileSync(LOCK_PATH, "utf8"), 10);
        if (pid && pid !== process.pid) {
          try { process.kill(pid, 0); } catch { fs.unlinkSync(LOCK_PATH); continue; }
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  if (fd === null) throw new Error("timed out waiting for install lock");

  try {
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
    return await body();
  } finally {
    try { fs.unlinkSync(LOCK_PATH); } catch {}
  }
}

// Render a simple progress line (carriage-return overwrite) when the caller
// enabled progress output.
function makeProgressReporter({ silent }) {
  if (silent || !process.stderr.isTTY) return null;
  let last = 0;
  return ({ current, total }) => {
    const pct = Math.floor((current / total) * 100);
    if (pct === last) return;
    last = pct;
    const width = 20;
    const filled = Math.floor((pct / 100) * width);
    const bar = "#".repeat(filled) + "-".repeat(width - filled);
    const mb = (n) => Math.round(n / 1048576);
    process.stderr.write(
      `\rmicrosandbox: [${bar}] ${pct}%  ${mb(current)}/${mb(total)} MB`,
    );
    if (current === total) process.stderr.write("\n");
  };
}

// Ensure ~/.microsandbox/bin/msb exists and matches PREBUILT_VERSION.
// No-ops when already installed. Returns the absolute path to msb.
//
// When `opts.ephemeralStatus` is true and stderr is a TTY, status and
// progress output is wiped on success using ANSI save/restore (so the shim
// leaves the terminal clean before exec'ing msb). Failures and non-TTY
// output are preserved so logs and redirected invocations stay readable.
async function ensureMsb(opts = {}) {
  const { silent = false, ephemeralStatus = false } = opts;

  if (isInstalled()) return msbPath();

  return withLock(async () => {
    // Re-check after acquiring the lock (another shim may have finished
    // the install while we were blocked).
    if (isInstalled()) return msbPath();

    const targetOS = getOS();
    const arch = getArch();
    const libkrunfw = libkrunfwFilename(targetOS);

    fs.mkdirSync(BIN_DIR, { recursive: true });
    fs.mkdirSync(LIB_DIR, { recursive: true });

    if (installCiLocalBundle(libkrunfw)) {
      if (!silent) console.error("microsandbox: installed runtime dependencies from local CI build/");
      return msbPath();
    }

    const ansi = ephemeralStatus && !silent && process.stderr.isTTY;
    if (ansi) process.stderr.write("\x1b[s");
    if (!silent) {
      process.stderr.write(
        `microsandbox: preparing runtime v${PREBUILT_VERSION} (first run only)...\n`,
      );
    }
    const url = bundleUrl(PREBUILT_VERSION, arch, targetOS);
    const data = await download(url, makeProgressReporter({ silent }));

    extractBundle(data);

    for (const [linkName, target] of libkrunfwSymlinks(libkrunfw, targetOS)) {
      const linkPath = path.join(LIB_DIR, linkName);
      try { fs.unlinkSync(linkPath); } catch {}
      fs.symlinkSync(target, linkPath);
    }

    if (!fs.existsSync(msbPath())) {
      throw new Error("msb binary not found after extraction");
    }
    if (!fs.existsSync(path.join(LIB_DIR, libkrunfw))) {
      throw new Error(`${libkrunfw} not found after extraction`);
    }

    if (ansi) {
      process.stderr.write("\x1b[u\x1b[J");
    } else if (!silent) {
      process.stderr.write("microsandbox: runtime ready.\n");
    }
    return msbPath();
  });
}

module.exports = { ensureMsb, isInstalled, msbPath, PREBUILT_VERSION };
