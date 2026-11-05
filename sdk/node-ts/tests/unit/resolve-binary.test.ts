import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const triple = process.platform === "darwin" ? "darwin-arm64"
  : process.platform === "win32" ? `win32-${process.arch}-msvc` : `linux-${process.arch}-gnu`;
const executable = process.platform === "win32" ? "msb.exe" : "msb";
let root: string;
let sdk: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "msb-resolver-")));
  sdk = join(root, "sdk");
  mkdirSync(sdk);
  writeFileSync(join(sdk, "package.json"), JSON.stringify({ type: "module", exports: "./resolver.js" }));
  // Copy the built resolver into an isolated file-linked SDK so installed
  // checkout platform packages cannot satisfy its import.meta.url lookup.
  copyFileSync(resolve("dist/internal/resolve-binary.js"), join(sdk, "resolver.js"));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function platformPackage(base: string, binary = true): string {
  const pkg = join(base, "node_modules", "@superradcompany", `microsandbox-${triple}`);
  mkdirSync(join(pkg, "bin"), { recursive: true });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: `microsandbox-${triple}` }));
  const msb = join(pkg, "bin", executable);
  if (binary) writeFileSync(msb, "resolver fixture: never execute");
  return msb;
}
function run(cwd: string, argv?: string): string | null {
  const consumer = argv ? dirname(argv) : cwd;
  mkdirSync(join(consumer, "node_modules"), { recursive: true });
  symlinkSync(sdk, join(consumer, "node_modules", "microsandbox"), process.platform === "win32" ? "junction" : "dir");
  const code = `import { msbPath } from 'microsandbox';
    console.log(JSON.stringify(msbPath()));`;
  // Use actual runtime argv/cwd rather than changing the Vitest process globals.
  if (argv) writeFileSync(argv, code);
  const args = argv ? [argv] : ["--input-type=module", "-e", code];
  // Bun must resolve only the fixture packages, not auto-install a missing
  // package from the registry when probing the isolated SDK directory.
  if (process.versions.bun) args.unshift("--no-install");
  const result = spawnSync(process.execPath, args, { cwd, encoding: "utf8", timeout: 30000 });
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout);
}

describe("SDK packaged binary resolver", () => {
  const names = ["ordinary", "hash#name", "percent%name", "encoded%2Fname", "encoded%23name", "space name", "中文", ...(process.platform === "win32" ? [] : ["query?name"])];
  for (const fallback of ["cwd", "argv"] as const) {
    // Bun cannot launch an entrypoint whose path contains `?`. Node still
    // covers that argv case; Bun covers the same character through cwd.
    const supportedNames = names.filter((name) =>
      !(process.versions.bun && fallback === "argv" && name.includes("?")));
    it.each(supportedNames)(`${fallback} resolves the exact package in %s`, (name) => {
      const consumer = join(root, name);
      mkdirSync(consumer);
      const expected = platformPackage(consumer);
      // Catch URL truncation or decoding selecting an unrelated sibling.
      platformPackage(join(root, "hash"));
      platformPackage(join(root, "query"));
      platformPackage(join(root, "encoded#name"));
      const elsewhere = join(root, "elsewhere");
      mkdirSync(elsewhere);

      expect(run(fallback === "cwd" ? consumer : elsewhere,
        fallback === "argv" ? join(consumer, "app.mjs") : undefined)).toBe(expected);
    });
  }
  it("keeps the SDK package ahead of consumer fallbacks", () => {
    const expected = platformPackage(sdk);
    const consumer = join(root, "consumer");
    mkdirSync(consumer);
    platformPackage(consumer);

    expect(run(consumer)).toBe(expected);
  });
  it("prefers the argv package over the cwd package", () => {
    const consumer = join(root, "argv#consumer");
    const cwd = join(root, "cwd%consumer");
    mkdirSync(consumer);
    mkdirSync(cwd);
    const expected = platformPackage(consumer);
    platformPackage(cwd);

    expect(run(cwd, join(consumer, "app.mjs"))).toBe(expected);
  });
  it("skips packages without a bundled binary and tries the next base", () => {
    platformPackage(sdk, false);
    const consumer = join(root, "incomplete#argv");
    const cwd = join(root, "complete%cwd");
    mkdirSync(consumer);
    mkdirSync(cwd);
    platformPackage(consumer, false);
    const expected = platformPackage(cwd);

    expect(run(cwd, join(consumer, "app.mjs"))).toBe(expected);
  });
  it("returns null when no platform package exists", () => {
    const consumer = join(root, "absent");
    mkdirSync(consumer);

    expect(run(consumer)).toBeNull();
  });
  it("returns null when the package has no bundled binary", () => {
    const consumer = join(root, "missing#binary");
    mkdirSync(consumer);
    platformPackage(consumer, false);

    expect(run(consumer)).toBeNull();
  });
  it("resolves an argv path through a directory symlink", () => {
    const consumer = join(root, "target#directory");
    mkdirSync(consumer);
    const expected = platformPackage(consumer);
    const alias = join(root, "alias%2Fdirectory");
    symlinkSync(consumer, alias, process.platform === "win32" ? "junction" : "dir");
    const elsewhere = join(root, "elsewhere");
    mkdirSync(elsewhere);

    expect(run(elsewhere, join(alias, "app.mjs"))).toBe(expected);
  });
});
