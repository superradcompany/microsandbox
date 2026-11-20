import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const root = fileURLToPath(new URL("../../", import.meta.url));
const target = process.platform + "-" + process.arch + (process.platform === "linux" ? "-gnu" : process.platform === "win32" ? "-msvc" : "");

it("imports the shared core without a native provider and explains missing providers", () => {
  const temp = mkdtempSync(join(tmpdir(), "msb-core-only-"));
  try {
    const staged = spawnSync(process.execPath, [join(root, "scripts/stage-distribution.mjs"), "--out", temp], { encoding: "utf8" });
    expect(staged.status, staged.stderr).toBe(0);
    const modules = join(temp, "node_modules", "@microsandbox");
    mkdirSync(modules, { recursive: true });
    symlinkSync(join(root, "../../packages/microsandbox-types/typescript"), join(modules, "types"), "dir");
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      const sdk = await import(${JSON.stringify(`file://${temp}/core/dist/index.js`)});
      assert.equal(typeof sdk.Sandbox, 'function');
      assert.equal(typeof sdk.Volume, 'function');
      assert.equal(typeof sdk.Snapshot, 'function');
      assert.throws(() => new sdk.LocalContext(), new RegExp("Install and import @microsandbox/local"));
      assert.throws(() => new sdk.RemoteContext({apiKey:'key'}), new RegExp("Install and import @microsandbox/remote"));
    `], { encoding: "utf8", timeout: 10000 });
    expect(result.status, result.stderr).toBe(0);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

const local = process.env.MSB_NODE_LOCAL_PROVIDER;
const remote = process.env.MSB_NODE_REMOTE_PROVIDER;
const full = process.env.MSB_NODE_FULL_PROVIDER;
it.skipIf(!local || !remote)("coexists with distinct local and remote native libraries", () => {
  const temp = mkdtempSync(join(tmpdir(), "msb-providers-"));
  try {
    const staged = spawnSync(process.execPath, [join(root, "scripts/stage-distribution.mjs"), "--out", temp,
      "--target", target, "--local-binding", local!, "--remote-binding", remote!, ...(full ? ["--full"] : [])], { encoding: "utf8" });
    expect(staged.status, staged.stderr).toBe(0);
    const modules = join(temp, "node_modules", "@microsandbox");
    mkdirSync(modules, { recursive: true });
    for (const name of ["core", "local", "remote", `local-${target}`, `remote-${target}`]) {
      symlinkSync(join(temp, name), join(modules, name), "dir");
    }
    // Reuse the locally built common types package without fetching a registry.
    cpSync(join(root, "../../packages/microsandbox-types/typescript"), join(modules, "types"), { recursive: true, filter: p => !p.includes("node_modules") });
    if (full) cpSync(full, join(temp, "full/native", `microsandbox.${target}.node`));
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import {createServer} from 'node:http';
      const full = ${JSON.stringify(full ? `file://${temp}/full/dist/index.js` : null)};
      let fullSdk, originalDefault;
      const providers = await import(${JSON.stringify(`file://${temp}/core/dist/internal/provider.js`)});
      if (full) {
        fullSdk = await import(full);
        originalDefault = providers.defaultBinding();
        assert.equal(JSON.parse(originalDefault.providerInfo()).remote, true);
      }
      const remote = await import(${JSON.stringify(`file://${temp}/remote/index.js`)});
      const selected = new remote.RemoteContext({url:'http://127.0.0.1:1',apiKey:'key'});
      const remoteBuilder = selected.sandboxes.builder('task').image('python');
      const local = await import(${JSON.stringify(`file://${temp}/local/index.js`)});
      assert.equal(local.Sandbox, remote.Sandbox);
      assert.equal(local.Volume, remote.Volume);
      assert.equal(local.Snapshot, remote.Snapshot);
      if (fullSdk) {
        assert.equal(fullSdk.Sandbox, local.Sandbox);
        assert.equal(providers.defaultBinding(), originalDefault);
      }
      const destination = new local.LocalContext({home:${JSON.stringify(join(temp, "home"))}});
      const localBuilder = destination.sandboxes.builder('other').image('python');
      assert.equal((await remoteBuilder.build()).name, 'task');
      assert.equal((await localBuilder.build()).name, 'other');
      assert.equal(selected.kind, 'remote');
      assert.equal(destination.kind, 'local');
      const server = createServer((req,res) => {
        assert.equal(req.headers.authorization, 'Bearer key');
        res.setHeader('content-type','application/json');
        res.end(JSON.stringify({id:'original',org_id:'org',name:'task',slug:'task',status:'stopped',ephemeral:false,created_at:'2026-11-16T00:00:00Z'}));
      });
      await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
      try {
        const context = new remote.RemoteContext({url:'http://127.0.0.1:'+server.address().port,apiKey:'key'});
        process.env.MSB_BACKEND = 'remote';
        process.env.MSB_API_URL = 'http://127.0.0.1:'+server.address().port;
        process.env.MSB_API_KEY = 'key';
        const sb = await local.Sandbox.get('task');
        assert.equal((await context.sandboxes.get('task')).id, sb.id);
        process.env.MSB_BACKEND = 'local';
        assert(sb instanceof local.Sandbox);
        assert.equal(sb.context.kind, 'remote');
        assert.equal((await sb.info()).id, sb.id);
        const {nativeOwner} = await import(${JSON.stringify(`file://${temp}/core/dist/internal/provider.js`)});
        const owner = nativeOwner(sb.inner);
        assert.equal(JSON.parse(owner.providerInfo()).local, false);
        // These exports must exist in the remote library and refuse local-only
        // observation rather than being hidden by a full/local build.
        await assert.rejects(sb.resizeStatus(), local.UnsupportedError);
        await assert.rejects(sb.resizeOperations(), local.UnsupportedError);
        await assert.rejects(sb.waitUntilResized(), local.UnsupportedError);
        const marker = new Error('configured');
        await assert.rejects(sb.execWith('true', options => {
          assert.equal(nativeOwner(options), owner);
          throw marker;
        }), error => error === marker);
        assert.equal((await sb.context.sandboxes.get('task')).id, sb.id);
      } finally { await new Promise(resolve=>server.close(resolve)); }
    `], { cwd: temp, env: { ...process.env, MSB_HOME: join(temp, "home"), MSB_CONFIG_PATH: join(temp, "config.json") }, encoding: "utf8", timeout: 15000 });
    expect(result.error, result.stderr).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
