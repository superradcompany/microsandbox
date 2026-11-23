import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { once } from "node:events";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as sdk from "../../dist/index.js";

describe("explicit destination selection", () => {
  it("does not expose mutable default routing", () => {
    for (const name of ["setDefaultBackend", "withDefaultBackend", "defaultBackendInfo", "defaultBackendKind"]) {
      expect(sdk).not.toHaveProperty(name);
    }
  });

  it("routes unqualified calls to the configured backend and keeps explicit local calls local", async () => {
    const dir = mkdtempSync(join(tmpdir(), "msb-context-"));
    const config = join(dir, "config.json");
    const hits: string[] = [];
    const server = createServer((req, res) => {
      hits.push(req.url ?? "");
      res.writeHead(422, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "selected provider" }));
    });
    try {
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Expected TCP listener");
      const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
      const url = "http://127.0.0.1:" + address.port;
      // Supply a real process environment to the native addon. Bun's JS-side
      // environment mutations are not visible to every native getenv consumer.
      const run = (script: string, backend?: string, key?: string) => {
        const env = { ...process.env, MSB_API_URL: url, MSB_CONFIG_PATH: config,
          MSB_HOME: join(dir, "runtime"), MSB_PROFILE: "" };
        const childEnv: NodeJS.ProcessEnv = { ...env, MSB_BACKEND: backend, MSB_API_KEY: key };
        if (backend === undefined) delete childEnv.MSB_BACKEND;
        if (key === undefined) delete childEnv.MSB_API_KEY;
        return promisify(execFile)(process.execPath, ["--input-type=module", "-e", `
          import assert from "node:assert/strict";
          import { Sandbox, Volume, Checkpoint, Snapshot, LocalContext, RemoteContext, SandboxNotFoundError } from ${JSON.stringify(moduleUrl)};
          ${script}
        `], { env: childEnv, timeout: 30_000 });
      };

      writeFileSync(config, "{}");
      await run(`
        assert.equal(new RemoteContext({url: process.env.MSB_API_URL, apiKey: "fixture"}).kind, "remote");
        assert.equal(new LocalContext().kind, "local");
        for (const resource of [Sandbox, Volume, Checkpoint]) {
          await assert.rejects(resource.list(), /selected provider/);
        }
        await assert.rejects(Snapshot.list(), /not supported/);
        await assert.rejects(Sandbox.local().get("absent"), SandboxNotFoundError);
      `, "cloud", "fixture");
      expect(hits).toHaveLength(3);
      await run(`
        await assert.rejects(Sandbox.get("absent"), SandboxNotFoundError);
        await assert.rejects(Sandbox.remote().get("absent"), /selected provider/);
      `, "local", "fixture");
      expect(hits).toHaveLength(4);
      await run('await assert.rejects(Sandbox.get("absent"), SandboxNotFoundError)', undefined, "fixture");
      writeFileSync(config, JSON.stringify({
        active_profile: "team",
        profiles: { team: { kind: "remote", url, api_key_ref: "env:MSB_API_KEY" } },
      }));
      await run("await assert.rejects(Sandbox.list(), /selected provider/)", undefined, "fixture");
      await run("await assert.rejects(Sandbox.list(), /MSB_API_KEY/)");
      expect(hits).toHaveLength(5);
    } finally {
      if (server.listening) await new Promise<void>(resolve => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("rejects local contexts prohibited by policy without creating storage", () => {
    const dir = mkdtempSync(join(tmpdir(), "msb-policy-"));
    try {
      const config = join(dir, "config.json");
      writeFileSync(config, JSON.stringify({ allowed_backends: ["cloud"] }));
      const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
      execFileSync(process.execPath, ["--input-type=module", "-e", `
        import assert from "node:assert/strict";
        import { LocalContext } from ${JSON.stringify(moduleUrl)};
        assert.throws(() => new LocalContext(), /local backend.*disabled/);
      `], { env: { ...process.env, MSB_CONFIG_PATH: config, MSB_HOME: join(dir, "runtime") }, timeout: 30_000 });
      expect(existsSync(join(dir, "runtime"))).toBe(false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
