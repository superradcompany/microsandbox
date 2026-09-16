import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const cli = resolve("bin/microsandbox.cjs");
const executable = process.platform === "win32" ? "msb.exe" : "msb";
const library = process.platform === "darwin" ? "libkrunfw.5.dylib"
  : process.platform === "win32" ? "libkrunfw.dll" : "libkrunfw.so.5.6.1";
let root: string;

function resolveMsb(packaged: () => string | null): { path: string; source: string } | null {
  // Bun caches os.homedir(), so HOME must be set before the process starts.
  // A fresh process also matches how users invoke the CLI with configuration.
  const code = `import { createRequire } from 'node:module';
    const { resolveMsb } = createRequire(import.meta.url)(${JSON.stringify(cli)});
    console.log(JSON.stringify(resolveMsb(() => ${JSON.stringify(packaged())})));`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    env: process.env, encoding: "utf8", timeout: 30000,
  });
  if (result.status !== 0) throw new Error(result.stderr || String(result.error));
  return JSON.parse(result.stdout);
}

function pair(home: string, marker = "runtime"): string {
  mkdirSync(join(home, "bin"), { recursive: true });
  mkdirSync(join(home, "lib"), { recursive: true });
  const msb = join(home, "bin", executable);
  writeFileSync(msb, `#!/bin/sh\nprintf '${marker}:%s\\n' "$*"\n`);
  chmodSync(msb, 0o755);
  writeFileSync(join(home, "lib", library), "fixture library");
  return msb;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "msb-resolution-"));
  vi.stubEnv("HOME", root);
  vi.stubEnv("USERPROFILE", root);
  for (const name of ["MSB_HOME", "MSB_PATH", "MSB_LIBKRUNFW_PATH", "MSB_CONFIG_PATH"]) {
    vi.stubEnv(name, undefined);
  }
});
afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(root, { recursive: true, force: true });
});

describe("CLI runtime precedence", () => {
  it.each([undefined, "", "custom"])("home precedes package with MSB_HOME=%s", (override) => {
    const home = override === "custom" ? join(root, "custom") : join(root, ".microsandbox");
    vi.stubEnv("MSB_HOME", override === "custom" ? home : override);
    const homeMsb = pair(home, "older");
    const packageMsb = pair(join(root, "package"), "newer");
    expect(resolveMsb(() => packageMsb)).toEqual({ path: homeMsb, source: "home" });
  });

  it("uses the package only for an absent home", () => {
    const msb = pair(join(root, "package"));
    expect(resolveMsb(() => msb)).toEqual({ path: msb, source: "platform-package" });
    expect(resolveMsb(() => null)).toBeNull();
  });

  it.each(["bin", "lib"])("rejects a home missing its %s half", (half) => {
    const home = join(root, ".microsandbox");
    pair(home);
    unlinkSync(join(home, half, half === "bin" ? executable : library));
    const msb = pair(join(root, "package"));
    expect(() => resolveMsb(() => msb)).toThrow("incomplete runtime");
  });

  it("keeps explicit overrides above a partial home", () => {
    const home = join(root, ".microsandbox");
    pair(home);
    unlinkSync(join(home, "lib", library));
    const msb = pair(join(root, "explicit"));
    vi.stubEnv("MSB_PATH", msb);
    expect(resolveMsb(() => null)?.path).toBe(msb);
    vi.stubEnv("MSB_PATH", join(root, "missing"));
    expect(() => resolveMsb(() => msb)).toThrow("incomplete runtime");
  });

  it("honors persisted home and binary paths", () => {
    const configured = pair(join(root, "configured"));
    const msb = pair(join(root, "package"));
    const config = join(root, "config.json");
    vi.stubEnv("MSB_CONFIG_PATH", config);
    writeFileSync(config, JSON.stringify({ home: join(root, "configured") }));
    expect(resolveMsb(() => msb)?.path).toBe(configured);
    writeFileSync(config, JSON.stringify({ paths: { msb } }));
    expect(resolveMsb(() => configured)?.path).toBe(msb);
  });

  it("requires an explicit executable for an environment library override", () => {
    vi.stubEnv("MSB_LIBKRUNFW_PATH", join(root, "library"));
    expect(() => resolveMsb(() => null)).toThrow("requires MSB_PATH");
  });

  it.skipIf(process.platform === "win32")("executes home and forwards arguments with a package present", () => {
    const stagedCli = join(root, "cli", "microsandbox.cjs");
    mkdirSync(dirname(stagedCli), { recursive: true });
    cpSync(cli, stagedCli);
    const triple = process.platform === "darwin" ? "darwin-arm64"
      : process.arch === "arm64" ? "linux-arm64-gnu" : "linux-x64-gnu";
    const pkg = join(root, "node_modules", "@superradcompany", `microsandbox-${triple}`);
    pair(pkg, "package");
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: `@superradcompany/microsandbox-${triple}` }));
    pair(join(root, ".microsandbox"), "home");
    const result = spawnSync(process.execPath, [stagedCli, "--version"], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("home:--version\n");
  });
});
