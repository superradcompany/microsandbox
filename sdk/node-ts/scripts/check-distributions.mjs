import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: {
  staged: { type: "string" }, types: { type: "string" }, target: { type: "string" },
  "full-platform": { type: "string" },
} });
if (!values.staged || !values.types || !values.target) throw new Error("--staged, --types and --target are required");
const temp = await mkdtemp(join(tmpdir(), "msb-package-check-"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", timeout: 120000,
    env: { ...process.env, npm_config_cache: join(temp, "cache") } });
  if (result.error || result.status !== 0) throw new Error(`${command} ${args.join(" ")}: ${result.error ?? result.stderr}\n${result.stdout}`);
  return result.stdout;
}
try {
  const packed = {};
  for (const name of ["core", "local", "remote", `local-${values.target}`, `remote-${values.target}`, "types"]) {
    const directory = name === "types" ? resolve(values.types) : resolve(values.staged, name);
    const metadata = JSON.parse(run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", temp], directory))[0];
    const files = metadata.files.map(file => file.path);
    if (name !== "types" && files.some(file => /(^|\/)(msb(?:\.exe)?|libkrunfw[^/]*|bin)(\/|$)/.test(file))) {
      throw new Error(`${name} includes runtime payload or launcher`);
    }
    if (["core", "local", "remote"].includes(name) && files.some(file => file.endsWith(".node"))) {
      throw new Error(`${name} includes a native platform payload`);
    }
    packed[name] = join(temp, metadata.filename);
  }
  for (const order of [["remote", "local"], ["local", "remote"]]) {
    const cwd = join(temp, order.join("-"));
    await mkdir(cwd);
    await writeFile(join(cwd, "package.json"), JSON.stringify({ private: true, type: "module" }));
    const install = names => run(npm, ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", ...names.map(name => packed[name])], cwd);
    install(["types", "core", order[0], `${order[0]}-${values.target}`]);
    install([order[1], `${order[1]}-${values.target}`]);
    run(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import * as local from '@microsandbox/local';
      import * as remote from '@microsandbox/remote';
      assert.equal(local.Sandbox,remote.Sandbox);
      assert.equal(local.Volume,remote.Volume);
      assert.equal(local.Snapshot,remote.Snapshot);
      assert.equal(new local.LocalContext().kind,'local');
      assert.equal(new remote.RemoteContext({apiKey:'test-key'}).kind,'remote');
    `], cwd);
    run(npm, ["uninstall", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", `@microsandbox/${order[0]}`, `@microsandbox/${order[0]}-${values.target}`], cwd);
    const kind = order[1];
    const expression = kind === "local" ? "new sdk.LocalContext()" : "new sdk.RemoteContext({apiKey:'test-key'})";
    run(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import * as sdk from '@microsandbox/${kind}';
      assert.equal(${expression}.kind,${JSON.stringify(kind)});
    `], cwd);
    const lock = JSON.parse(await readFile(join(cwd, "package-lock.json"), "utf8"));
    if (lock.packages["node_modules/microsandbox"]) throw new Error("lean package depends on the full SDK");
  }
  if (values["full-platform"]) {
    for (const [name, directory] of [["full", resolve(values.staged, "full")], ["full-platform", resolve(values["full-platform"])]]) {
      const metadata = JSON.parse(run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", temp], directory))[0];
      packed[name] = join(temp, metadata.filename);
    }
    for (const first of ["full", "lean"]) {
      const cwd = join(temp, `coexist-${first}`);
      await mkdir(cwd);
      await writeFile(join(cwd, "package.json"), JSON.stringify({ private: true, type: "module" }));
      const names = ["types", "core", "full", "full-platform", "local", "remote", `local-${values.target}`, `remote-${values.target}`];
      run(npm, ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", ...names.map(name => packed[name])], cwd);
      run(process.execPath, ["--input-type=module", "-e", `
        import assert from 'node:assert/strict';
        const first = ${JSON.stringify(first)};
        let full, local, remote, retained;
        if (first === 'full') {
          full = await import('microsandbox');
          retained = new full.LocalContext();
          full.Sandbox.builder('retained-default');
        }
        local = await import('@microsandbox/local');
        remote = await import('@microsandbox/remote');
        if (!full) full = await import('microsandbox');
        for (const type of ['Sandbox', 'Volume', 'Snapshot']) {
          assert.equal(full[type], local[type]);
          assert.equal(full[type], remote[type]);
        }
        assert.equal(new local.LocalContext().kind, 'local');
        assert.equal(new remote.RemoteContext({apiKey:'fixture'}).kind, 'remote');
        if (retained) assert.equal(retained.kind, 'local');
      `], cwd);
    }
    console.log("Full/lean class identity and provider loading passed in both import orders.");
  }
  console.log("Packed payload checks, offline installs, both provider install orders and independent uninstall passed.");
} finally {
  await rm(temp, { recursive: true, force: true });
}
