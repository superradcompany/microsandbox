import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

it("waits without returning a second resource or starting the sandbox", () => {
  const home = mkdtempSync(join(tmpdir(), "msb-wait-"));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
  const moduleUrl = new URL("../../dist/context.js", import.meta.url).href;
  try {
    // A fresh process isolates native destination caching from the other tests.
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { createServer } from "node:http";
      let observedStatus = "stopped";
      let requests = 0;
      const server = createServer((request, response) => {
        assert.equal(request.method, "GET");
        assert.equal(request.url, "/v1/sandboxes/by-name/task");
        requests++;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({id:"original", org_id:"org", name:"task",
          slug:"task", status:observedStatus, ephemeral:false, created_at:"2026-11-16T00:00:00Z"}));
      });
      await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
      process.env.MSB_BACKEND = "cloud";
      process.env.MSB_API_KEY = "test-key";
      process.env.MSB_API_URL = "http://127.0.0.1:" + server.address().port;
      try {
        const { RemoteContext } = await import(${JSON.stringify(moduleUrl)});
        const remote = new RemoteContext({url: process.env.MSB_API_URL, apiKey: "test-key"});
        const sb = await remote.sandboxes.get("task");
        const identity = sb.id;
        assert.equal(await sb.waitForStatus("stopped"), undefined);
        assert.equal(sb.id, identity);
        observedStatus = "running";
        assert.equal((await sb.info()).status, "running");
        assert.equal(requests, 4);
      } finally { await new Promise(resolve => server.close(resolve)); }
    `], { env: { ...env, MSB_HOME: home }, encoding: "utf8", timeout: 15000 });
    expect(result.error, result.stderr).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
