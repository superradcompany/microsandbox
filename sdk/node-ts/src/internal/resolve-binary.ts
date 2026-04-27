import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

function detectTriple(): string {
  const p = process.platform;
  const a = process.arch;
  if (p === "darwin" && a === "arm64") return "darwin-arm64";
  if (p === "linux" && a === "x64") return "linux-x64-gnu";
  if (p === "linux" && a === "arm64") return "linux-arm64-gnu";
  throw new Error(`microsandbox: unsupported platform ${p}-${a}`);
}

// Search from multiple roots so the platform package resolves whether
// the SDK was installed normally (the platform pkg sits beside the
// consumer's `node_modules/microsandbox/`) or via a `file:` link (in
// which case `import.meta.url` follows symlinks back to the SDK source,
// where no platform pkg is installed).
function resolutionBases(): string[] {
  const bases = new Set<string>();
  bases.add(import.meta.url);
  if (process.argv[1]) bases.add(`file://${process.argv[1]}`);
  bases.add(`file://${process.cwd()}/`);
  return Array.from(bases);
}

function resolvePlatformRoot(): string | null {
  const triple = detectTriple();
  for (const base of resolutionBases()) {
    try {
      const r = createRequire(base);
      const pkgPath = r.resolve(
        `@superradcompany/microsandbox-${triple}/package.json`,
      );
      const root = dirname(pkgPath);
      // Only accept this base if it actually carries the bundled binaries —
      // the published 0.x platform package may exist in the resolver's
      // path with only the .node file.
      if (existsSync(join(root, "bin", "msb"))) return root;
    } catch {
      // try next base
    }
  }
  return null;
}

let cached: { binDir: string; libDir: string } | null = null;

function resolvePlatformPaths(): { binDir: string; libDir: string } {
  if (cached) return cached;
  const root = resolvePlatformRoot();
  if (root) {
    cached = { binDir: join(root, "bin"), libDir: join(root, "lib") };
    return cached;
  }
  // Fall back to ~/.microsandbox if no platform package carries binaries.
  const home = process.env.HOME ?? "";
  const fallback = join(home, ".microsandbox");
  cached = { binDir: join(fallback, "bin"), libDir: join(fallback, "lib") };
  return cached;
}

/** Path to the bundled `msb` binary, or null if not yet installed. */
export function msbPath(): string | null {
  const explicit = process.env.MSB_PATH;
  if (explicit) return existsSync(explicit) ? explicit : null;
  const p = join(resolvePlatformPaths().binDir, "msb");
  return existsSync(p) ? p : null;
}

/** Path to the bundled `libkrunfw` shared library, or null. */
export function libkrunfwPath(): string | null {
  const filename =
    process.platform === "darwin" ? "libkrunfw.dylib" : "libkrunfw.so";
  const p = join(resolvePlatformPaths().libDir, filename);
  return existsSync(p) ? p : null;
}
