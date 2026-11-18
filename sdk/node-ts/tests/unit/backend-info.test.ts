import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

  it("routes unqualified calls to the configured backend and keeps explicit local calls local", () => {
    const dir = mkdtempSync(join(tmpdir(), "msb-context-"));
    try {
      const config = join(dir, "config.json");
      writeFileSync(config, "{}");
      const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
      const script = `
        import assert from "node:assert/strict";
        import { Sandbox, LocalContext, RemoteContext, SandboxNotFoundError } from ${JSON.stringify(moduleUrl)};
        const remote = new RemoteContext({url: "http://127.0.0.1:9", apiKey: "fixture"});
        assert.equal(remote.kind, "remote");
        assert.equal(new LocalContext().kind, "local");
        const { createServer } = await import("node:http");
        const hits = [];
        const server = createServer((req, res) => {
          hits.push(req.url);
          res.writeHead(422, { "content-type": "application/json" });
          res.end(JSON.stringify({message: "selected provider"}));
        });
        await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
        process.env.MSB_API_URL = "http://127.0.0.1:" + server.address().port;
        try {
          const { Volume, Snapshot } = await import(${JSON.stringify(moduleUrl)});
          for (const resource of [Sandbox, Volume, Snapshot]) {
            await assert.rejects(resource.list(), /selected provider/);
          }
          assert.equal(hits.length, 3);
          await assert.rejects(Sandbox.local().get("absent"), SandboxNotFoundError);
          process.env.MSB_BACKEND = "local";
          await assert.rejects(Sandbox.get("absent"), SandboxNotFoundError);
          await assert.rejects(Sandbox.remote().get("absent"), /selected provider/);
          assert.equal(hits.length, 4);
          delete process.env.MSB_BACKEND;
          await assert.rejects(Sandbox.get("absent"), SandboxNotFoundError);
          const { writeFileSync } = await import("node:fs");
          writeFileSync(process.env.MSB_CONFIG_PATH, JSON.stringify({
            active_profile: "team",
            profiles: { team: { kind: "remote", url: process.env.MSB_API_URL, api_key_ref: "env:MSB_API_KEY" } },
          }));
          await assert.rejects(Sandbox.list(), /selected provider/);
          assert.equal(hits.length, 5);
          delete process.env.MSB_API_KEY;
          await assert.rejects(Sandbox.list(), /MSB_API_KEY/);
          assert.equal(hits.length, 5);
        } finally { await new Promise(resolve => server.close(resolve)); }
      `;
      execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        env: { ...process.env, MSB_BACKEND: "cloud", MSB_API_KEY: "fixture", MSB_API_URL: "http://127.0.0.1:9", MSB_CONFIG_PATH: config, MSB_HOME: join(dir, "runtime"), MSB_PROFILE: "" },
        timeout: 30_000,
      });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

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
