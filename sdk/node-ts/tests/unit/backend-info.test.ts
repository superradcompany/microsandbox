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

  it("keeps shortcuts local despite remote environment selection", () => {
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
        await assert.rejects(Sandbox.get("absent"), SandboxNotFoundError);
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
