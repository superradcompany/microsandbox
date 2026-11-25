import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

it("captures configured metadata and credentials before resource creation", () => {
  const directory = mkdtempSync(join(tmpdir(), "msb-configured-context-"));
  try {
    const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
    const result = execFileSync(process.execPath, ["--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { createServer } from "node:http";
      import { once } from "node:events";
      import { writeFileSync, existsSync } from "node:fs";
      import { configuredContext, RemoteContext } from ${JSON.stringify(moduleUrl)};
      const hits = [];
      const server = createServer((req, res) => {
        hits.push(req.headers.authorization);
        res.writeHead(200, {"content-type": "application/json"});
        res.end('{"data":[]}');
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const url = "http://127.0.0.1:" + server.address().port;
      const select = (name) => writeFileSync(process.env.MSB_CONFIG_PATH, JSON.stringify({
        active_profile: name, profiles: {
          prod: {kind: "remote", url, api_key_ref: "env:MSB_TEST_CONTEXT_KEY"},
          staging: {kind: "remote", url: "http://127.0.0.1:9", api_key_ref: "env:MSB_TEST_CONTEXT_KEY"},
        },
      }));
      try {
        select("prod");
        const destination = configuredContext();
        assert.ok(destination instanceof RemoteContext);
        const info = destination.info;
        assert.deepEqual(info, {kind: "remote", source: "active_profile", profile: "prod", apiUrl: url});
        assert.ok(Object.isFrozen(info));
        assert.ok(!JSON.stringify(info).includes("captured-secret"));
        assert.equal(hits.length, 0);
        assert.ok(!existsSync(process.env.MSB_HOME));
        select("staging");
        process.env.MSB_TEST_CONTEXT_KEY = "changed-secret";
        await destination.sandboxes.list();
        assert.deepEqual(hits, ["Bearer captured-secret"]);
        assert.deepEqual(destination.info, info);
        assert.equal(configuredContext().info.profile, "staging");
        process.env.MSB_PROFILE = "prod";
        assert.equal(configuredContext().info.source, "MSB_PROFILE");
        process.env.MSB_BACKEND = "local";
        assert.equal(configuredContext().info.kind, "local");
        assert.equal(configuredContext().info.source, "MSB_BACKEND");
        delete process.env.MSB_BACKEND;
        process.env.MSB_PROFILE = "missing";
        assert.throws(() => configuredContext(), /missing/);
      } finally { server.closeAllConnections(); server.close(); }
    `], { env: {...env, MSB_TEST_CONTEXT_KEY: "captured-secret", MSB_CONFIG_PATH: join(directory, "config.json"), MSB_HOME: join(directory, "home")}, timeout: 30_000 });
    expect(result.length).toBe(0);
  } finally { rmSync(directory, {recursive: true, force: true}); }
}, 35_000);
