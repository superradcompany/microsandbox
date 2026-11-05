import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { defaultBackendInfo, defaultBackendKind } from "../../dist/index.js";

describe("backend introspection", () => {
  it("reports prohibited selection through both diagnostics", () => {
    // Requires an unmanaged host; subprocesses retain system policy. See DEVELOPMENT.md.
    const dir = mkdtempSync(join(tmpdir(), "msb-context-"));
    try {
      const config = join(dir, "config.json");
      writeFileSync(config, JSON.stringify({ allowed_backends: ["cloud"] }));
      const env = Object.fromEntries(
        Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")),
      );
      const moduleUrl = new URL("../../dist/index.js", import.meta.url).href;
      const script = `
        import assert from "node:assert/strict";
        import { defaultBackendInfo, defaultBackendKind } from ${JSON.stringify(moduleUrl)};
        for (const diagnostic of [defaultBackendInfo, defaultBackendKind]) {
          assert.throws(diagnostic, /local backend.*disabled/);
        }
      `;
      execFileSync(process.execPath, ["--input-type=module", "-e", script], {
        env: { ...env, MSB_CONFIG_PATH: config, MSB_HOME: join(dir, "runtime") },
        timeout: 30_000,
      });
      expect(existsSync(join(dir, "runtime"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns structured, secret-safe default backend information", () => {
    const info = defaultBackendInfo();

    expect(["local", "cloud"]).toContain(info.kind);
    expect(info.kind).toBe(defaultBackendKind());
    expect(info).not.toHaveProperty("apiKey");
    expect(info).not.toHaveProperty("api_key");
    if (info.kind === "cloud") {
      expect(info.apiUrl).toMatch(/^https?:\/\//);
    } else {
      expect(info.apiUrl).toBeUndefined();
    }
  });
});
