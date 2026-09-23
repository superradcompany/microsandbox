import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

function detectTriple(): string {
  const p = process.platform;
  const a = process.arch;
  if (p === "darwin" && a === "arm64") return "darwin-arm64";
  if (p === "linux" && a === "x64") return "linux-x64-gnu";
  if (p === "linux" && a === "arm64") return "linux-arm64-gnu";
  if (p === "win32" && a === "x64") return "win32-x64-msvc";
  if (p === "win32" && a === "arm64") return "win32-arm64-msvc";
  throw new Error(`microsandbox: unsupported platform ${p}-${a}`);
}

function msbFileName(): string {
  return process.platform === "win32" ? "msb.exe" : "msb";
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
      if (existsSync(join(root, "bin", msbFileName()))) return root;
    } catch {
      // try next base
    }
  }
  return null;
}

/** Discover only packaged binaries; the Rust resolver owns home precedence. */
export function msbPath(): string | null {
  const root = resolvePlatformRoot();
  return root ? join(root, "bin", msbFileName()) : null;
}
