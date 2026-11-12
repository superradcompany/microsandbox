import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const FIXTURES = fileURLToPath(
  new URL("../../../../packages/microsandbox-types/rust/lib/cloud/fixtures/", import.meta.url),
);

it("passes Service results and change outcomes through from the native SDK", () => {
  const home = mkdtempSync(join(tmpdir(), "msb-service-native-"));
  // A fresh process isolates the process-global backend; every request goes to a local fake.
  const env: NodeJS.ProcessEnv = {
    ...process.env, MSB_HOME: home, MSB_CONFIG_PATH: join(home, "config.json"),
    SERVICE_FIXTURES: FIXTURES,
  };
  delete env.MSB_PROFILE;
  delete env.MSB_BACKEND;
  const script = `
    import assert from "node:assert/strict";
    import { readFileSync } from "node:fs";
    import { createServer } from "node:http";
    import { join } from "node:path";
    import { Service } from "./dist/service.js";
    import { setDefaultBackend } from "./dist/runtime.js";
    import {
      InvalidConfigError, ServiceError, ServiceNotFoundError, UnsupportedError,
    } from "./dist/errors.js";

    const fixture = (name) => readFileSync(join(process.env.SERVICE_FIXTURES, name), "utf8");
    const scenario = JSON.parse(fixture("service-binding-scenario.json"));
    const requests = [];
    const server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => { body += chunk; });
      request.on("end", () => {
        const route = request.method + " " + request.url;
        requests.push({ route, body });
        const answer = scenario.answers[route] ?? { status: 404 };
        response.writeHead(answer.status, { "content-type": "application/json", ...answer.headers });
        response.end(
          answer.body_fixture ? fixture(answer.body_fixture)
            : answer.body === undefined ? "" : JSON.stringify(answer.body),
        );
      });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    setDefaultBackend({
      kind: "cloud", url: "http://127.0.0.1:" + server.address().port, apiKey: "test",
    });

    const svc = await Service.builder("shop").target("web-1", 8080).create();
    assert.equal(svc.url, "https://shop.<domain>");
    assert.equal(svc.status, "enabled");
    assert.deepEqual(svc.target, { sandbox: "web-1", port: 8080 });
    assert.equal(svc.updatedAt.toISOString(), "2026-10-26T10:05:00.000Z");

    const unreachable = await svc.enable().catch((error) => error);
    assert(unreachable instanceof ServiceError, String(unreachable));
    assert.equal(unreachable.slug, "shop");
    assert.equal(unreachable.reason, "targetUnreachable");
    assert.equal(unreachable.retryAfterMs, 5000);
    assert.equal(unreachable.changed, "unchanged");

    const lost = await svc.remove().catch((error) => error);
    assert(lost instanceof ServiceError, String(lost));
    assert.equal(lost.reason, "outcomeUnknown");
    assert.equal(lost.changed, "unknown");

    await assert.rejects(Service.get("gone"), ServiceNotFoundError);
    for (const limit of [-1, 0, 1.5, 101]) {
      await assert.rejects(Service.listWith((l) => l.limit(limit)), RangeError);
    }
    for (const port of [-1, 0, 1.5, 70000]) {
      await assert.rejects(
        Service.builder("shop").target("web-1", port).create(),
        RangeError,
      );
      await assert.rejects(
        svc.update({ target: { sandbox: "web-2", port } }),
        RangeError,
      );
    }
    const missingTarget = await Service.builder("shop").create().catch((error) => error);
    assert(missingTarget instanceof InvalidConfigError, String(missingTarget));
    assert.equal(missingTarget.changed, "unchanged");
    assert.deepEqual(requests.map((r) => r.route), scenario.requests.map((r) => r.route));
    scenario.requests.forEach((expected, index) => {
      if (expected.body !== undefined) {
        assert.deepEqual(JSON.parse(requests[index].body), expected.body, expected.route);
      }
    });

    setDefaultBackend("local");
    const retained = await svc.enable().catch((error) => error);
    assert(retained instanceof ServiceError, String(retained));
    await assert.rejects(Service.get("shop"), UnsupportedError);
    await assert.rejects(Service.list(), UnsupportedError);
    const unsupportedChange = await Service.builder("shop").target("web-1", 8080).create()
      .catch((error) => error);
    assert(unsupportedChange instanceof UnsupportedError, String(unsupportedChange));
    assert.equal(unsupportedChange.changed, "unchanged");
    server.close();
  `;
  try {
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
      env,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(result.status, result.stderr || result.stdout).toBe(0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
