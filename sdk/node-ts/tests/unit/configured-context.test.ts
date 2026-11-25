import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
      const select = (name, keyRef = "env:MSB_TEST_CONTEXT_KEY") => writeFileSync(process.env.MSB_CONFIG_PATH, JSON.stringify({
        active_profile: name, profiles: {
          prod: {kind: "remote", url, api_key_ref: keyRef},
          staging: {kind: "remote", url: "http://127.0.0.1:9", api_key_ref: keyRef},
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
        // Rotate the saved credentials as well as the selected profile. File
        // changes are visible to native code under both Node and Bun.
        select("staging", "inline:changed-secret");
        await destination.sandboxes.list();
        assert.deepEqual(hits, ["Bearer captured-secret"]);
        assert.deepEqual(destination.info, info);
        assert.equal(configuredContext().info.profile, "staging");
      } finally { server.closeAllConnections(); server.close(); }
    `], { env: {...env, MSB_TEST_CONTEXT_KEY: "captured-secret", MSB_CONFIG_PATH: join(directory, "config.json"), MSB_HOME: join(directory, "home")}, timeout: 30_000 });
    expect(result.length).toBe(0);
  } finally { rmSync(directory, {recursive: true, force: true}); }
}, 35_000);

// Bun's JS-side environment mutations are not reliably visible to native getenv.
// Supply each override at launch so these cases exercise real Rust precedence.
it.each([
  { name: "MSB_PROFILE overrides the saved profile", overrides: { MSB_PROFILE: "prod" },
    expected: { kind: "remote", source: "MSB_PROFILE", profile: "prod", apiUrl: "http://127.0.0.1:9" } },
  { name: "MSB_BACKEND overrides MSB_PROFILE", overrides: { MSB_PROFILE: "prod", MSB_BACKEND: "local" },
    expected: { kind: "local", source: "MSB_BACKEND" } },
  { name: "an invalid profile fails during resolution", overrides: { MSB_PROFILE: "missing" },
    expected: { error: "missing" } },
])("$name", ({ overrides, expected }) => {
  const directory = mkdtempSync(join(tmpdir(), "msb-context-override-"));
  try {
    const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
    const configPath = join(directory, "config.json");
    writeFileSync(configPath, JSON.stringify({
      active_profile: "staging",
      profiles: {
        prod: { kind: "remote", url: "http://127.0.0.1:9", api_key_ref: "env:MSB_TEST_CONTEXT_KEY" },
        staging: { kind: "local" },
      },
    }));
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
    const result = execFileSync(process.execPath, ["--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { existsSync } from "node:fs";
      import { configuredContext, InvalidConfigError } from ${JSON.stringify(moduleUrl)};
      const expected = ${JSON.stringify(expected)};
      if (expected.error) {
        assert.throws(() => configuredContext(), error =>
          error instanceof InvalidConfigError && error.message.includes(expected.error));
      } else {
        const info = configuredContext().info;
        assert.equal(info.kind, expected.kind);
        assert.equal(info.source, expected.source);
        assert.equal(info.profile, expected.profile);
        assert.equal(info.apiUrl, expected.apiUrl);
      }
      assert.ok(!existsSync(process.env.MSB_HOME));
    `], { env: { ...env, MSB_TEST_CONTEXT_KEY: "fixture-key", MSB_CONFIG_PATH: configPath,
      MSB_HOME: join(directory, "home"), ...overrides }, timeout: 15_000 });
    expect(result.length).toBe(0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
