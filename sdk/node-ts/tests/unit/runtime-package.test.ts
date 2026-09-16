import { spawnSync } from "node:child_process";
import { constants, copyFileSync, cpSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, expect, it } from "vitest";

let entry: string;
let nativeEntry: string;
const executable = process.platform === "win32" ? "msb.exe" : "msb";
const library = process.platform === "darwin" ? "libkrunfw.5.dylib"
  : process.platform === "win32" ? "libkrunfw.dll" : "libkrunfw.so.5.6.1";
const triple = process.platform === "darwin" ? "darwin-arm64"
  : process.platform === "win32" ? `win32-${process.arch}-msvc` : `linux-${process.arch}-gnu`;
let root: string;
let packageRoot: string;
let env: NodeJS.ProcessEnv;
function pair(home: string) {
  mkdirSync(join(home, "bin"), { recursive: true });
  mkdirSync(join(home, "lib"), { recursive: true });
  writeFileSync(join(home, "bin", executable), "older runtime: do not execute");
  writeFileSync(join(home, "lib", library), "matching firmware");
}
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "msb-package-"));
  // Discovery starts at the SDK's own location before consulting cwd. Copy the
  // real SDK into the fixture so an installed CI platform package cannot leak
  // into tests that deliberately remove their packaged runtime.
  const sdkRoot = join(root, "node_modules", "microsandbox");
  cpSync(resolve("dist"), join(sdkRoot, "dist"), { recursive: true });
  // Reproduce the runtime dependency installed alongside the published SDK.
  const typesRoot = join(root, "node_modules", "@microsandbox", "types");
  cpSync(resolve("../../packages/microsandbox-types/typescript/dist"), join(typesRoot, "dist"), { recursive: true });
  copyFileSync(resolve("../../packages/microsandbox-types/typescript/package.json"), join(typesRoot, "package.json"));
  mkdirSync(join(sdkRoot, "native"));
  copyFileSync(resolve("package.json"), join(sdkRoot, "package.json"));
  copyFileSync(resolve("native/index.cjs"), join(sdkRoot, "native/index.cjs"));
  const addon = `microsandbox.${triple}.node`;
  copyFileSync(resolve("native", addon), join(sdkRoot, "native", addon), constants.COPYFILE_FICLONE);
  entry = pathToFileURL(join(sdkRoot, "dist/index.js")).href;
  nativeEntry = join(sdkRoot, "native/index.cjs");
  packageRoot = join(root, "node_modules", "@superradcompany", `microsandbox-${triple}`);
  pair(packageRoot);
  writeFileSync(join(packageRoot, "package.json"), JSON.stringify({ name: `@superradcompany/microsandbox-${triple}` }));
  env = { ...process.env, HOME: root, USERPROFILE: root };
  for (const name of ["MSB_HOME", "MSB_PATH", "MSB_LIBKRUNFW_PATH", "MSB_CONFIG_PATH"]) delete env[name];
  // Windows native home discovery uses the known-folder API, not USERPROFILE.
  // Select an isolated home explicitly so the user's real install cannot leak in.
  if (process.platform === "win32") env.MSB_HOME = join(root, ".microsandbox");
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
function installed(before = "") {
  // Import the real JS layer and native addon in a fresh process so automatic
  // registration, set-once overrides, and environment reads are all exercised.
  const code = `import { createRequire } from 'node:module';
    const sdk = await import(${JSON.stringify(entry)});
    const native = createRequire(import.meta.url)(${JSON.stringify(nativeEntry)});
    ${before}
    console.log(sdk.isRuntimeInstalled());`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    cwd: root, env, encoding: "utf8", timeout: 30000,
  });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}
it.each([process.platform === "win32" ? "isolated" : "default", "custom"])("native SDK prefers %s home over an incomplete package", (kind) => {
  const home = join(root, kind === "custom" ? "custom" : ".microsandbox");
  if (kind === "custom") env.MSB_HOME = home;
  pair(home);
  unlinkSync(join(packageRoot, "lib", library));
  expect(installed()).toBe("true");
});
it("native SDK uses package only when home is absent", () => {
  expect(installed()).toBe("true");
  const home = join(root, ".microsandbox");
  pair(home);
  unlinkSync(join(home, "lib", library));
  expect(installed()).toBe("false");
});
it("explicit setters still override a registered package and complete home", () => {
  pair(join(root, ".microsandbox"));
  expect(installed(`native.setRuntimeMsbPath(${JSON.stringify(join(root, "missing"))});`)).toBe("false");
});
it("package discovery does not pin default home when MSB_HOME is custom", () => {
  unlinkSync(join(packageRoot, "bin", executable));
  pair(join(root, ".microsandbox"));
  env.MSB_HOME = join(root, "absent-custom-home");
  expect(installed()).toBe("false");
});

function installSource(home: string) {
  pair(home);
  // Directory installation takes a flat release bundle, not an installed home.
  copyFileSync(join(home, "bin", executable), join(home, executable));
  copyFileSync(join(home, "lib", library), join(home, library));
}

function runSetup(script: string) {
  const code = `const sdk = await import(${JSON.stringify(entry)}); ${script}`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    cwd: root, env, encoding: "utf8", timeout: 30000,
  });
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout);
}

it("exports the four operations and removes legacy entry points", () => {
  expect(runSetup(`console.log(JSON.stringify([
    ...['resolveRuntime', 'isRuntimeInstalled', 'installRuntime', 'ensureRuntime'].map(n => typeof sdk[n]),
    ...['install', 'isInstalled', 'setup', 'Setup'].map(n => n in sdk)
  ]));`)).toEqual(["function", "function", "function", "function", false, false, false, false]);
});

it("returns the selected pair and ensure ignores acquisition for an existing home", () => {
  const home = join(root, "chosen");
  pair(home);
  const results = runSetup(`const config = {home: ${JSON.stringify(home)}};
    console.log(JSON.stringify([sdk.resolveRuntime(config), await sdk.ensureRuntime(config, {
      source: 'directory', sourcePath: '/absent-source', force: true, verify: false
    })]));`);
  expect(results).toEqual(Array(2).fill({msbPath: join(home, "bin", executable), libkrunfwPath: join(home, "lib", library), origin: "home"}));
});

it("installs an explicit directory and returns its pair even with a package present", () => {
  const home = join(root, "destination");
  installSource(packageRoot);
  const result = runSetup(`console.log(JSON.stringify(await sdk.installRuntime(
    {home: ${JSON.stringify(home)}}, {source: 'directory', sourcePath: ${JSON.stringify(packageRoot)}, verify: false}
  )));`);
  expect(result).toEqual({msbPath: join(home, "bin", executable), libkrunfwPath: join(home, "lib", library), origin: "installed"});
});

it("ensure installs only when absent and refuses partial homes", () => {
  // Remove package discovery while retaining a separate installation source.
  const source = join(root, "source");
  installSource(source);
  unlinkSync(join(packageRoot, "bin", executable));
  const home = join(root, "destination");
  const result = runSetup(`console.log(JSON.stringify(await sdk.ensureRuntime(
    {home: ${JSON.stringify(home)}}, {source: 'directory', sourcePath: ${JSON.stringify(source)}, verify: false}
  )));`);
  expect(result.origin).toBe("installed");
  unlinkSync(join(home, "lib", library));
  expect(runSetup(`try {
    await sdk.ensureRuntime({home: ${JSON.stringify(home)}}, {source: 'directory', sourcePath: ${JSON.stringify(source)}, verify: false});
    throw new Error('unexpected success');
  } catch (e) { console.log(JSON.stringify(e.constructor.name)); }`)).toBe("RuntimeIncompleteError");
});
