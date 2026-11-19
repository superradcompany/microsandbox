import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

it("retains independent destinations through collections, builders and resources", () => {
  const home = mkdtempSync(join(tmpdir(), "msb-context-"));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
  const moduleUrl = new URL("../../dist/context.js", import.meta.url).href;
  const sandboxUrl = new URL("../../dist/sandbox.js", import.meta.url).href;
  try {
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { createServer } from "node:http";
      const requests = [];
      async function provider(id) {
        const server = createServer(async (req, res) => {
          requests.push([id, req.method, req.url]);
          assert.equal(req.headers.authorization, "Bearer key-" + id);
          res.setHeader("content-type", "application/json");
          if (req.method === "POST") {
            let body = "";
            for await (const chunk of req) body += chunk;
            requests.at(-1).push(JSON.parse(body).compute?.type);
            res.writeHead(403); res.end(JSON.stringify({error:"creation denied"})); return;
          }
          const resource = {id, org_id:"org", name:"task", slug:"task", status:"stopped", ephemeral:false, created_at:"2026-11-16T00:00:00Z"};
          res.end(JSON.stringify(req.url.split("?")[0] === "/v1/sandboxes" ? {data:[resource]} : resource));
        });
        await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
        return server;
      }
      const a = await provider("a"), b = await provider("b");
      try {
        const { RemoteContext, LocalContext } = await import(${JSON.stringify(moduleUrl)});
        const { Sandbox } = await import(${JSON.stringify(sandboxUrl)});
        let remote = RemoteContext.builder().url("http://127.0.0.1:" + a.address().port).apiKey("key-a").computeType("shared").build();
        assert.equal(new RemoteContext({apiKey:"hosted-key"}).kind, "remote");
        assert.throws(() => new RemoteContext({apiKey:""}));
        assert.throws(() => RemoteContext.withUrl("", "key"));
        assert.throws(() => RemoteContext.withUrl("http://localhost", "key", {requestTimeoutMs:-1}), RangeError);
        const { Volume } = await import(new URL("./volume.js", ${JSON.stringify(sandboxUrl)}));
        const { Snapshot } = await import(new URL("./snapshot.js", ${JSON.stringify(sandboxUrl)}));
        for (const resource of [Sandbox, Volume, Snapshot]) assert.throws(() => resource.remote());
        process.env.MSB_API_URL = "http://127.0.0.1:" + a.address().port;
        process.env.MSB_API_KEY = "key-a";
        process.env.MSB_BACKEND = "local";
        for (const resource of [Sandbox, Volume, Snapshot]) assert.equal(resource.remote().context.kind, "remote");
        const envBuilder = RemoteContext.builder().computeType("shared");
        const urlA = process.env.MSB_API_URL;
        for (const selected of [new RemoteContext(), envBuilder.build()]) {
          assert.equal((await selected.sandboxes.get("task")).id, "cloud:a");
        }
        process.env.MSB_API_KEY = "wrong";
        assert.equal((await RemoteContext.builder().apiKey("key-a").build().sandboxes.get("task")).id, "cloud:a");
        process.env.MSB_API_KEY = "key-a";
        process.env.MSB_API_URL = "http://127.0.0.1:" + b.address().port;
        assert.equal((await RemoteContext.builder().url(urlA).build().sandboxes.get("task")).id, "cloud:a");
        process.env.MSB_API_URL = urlA;
        const sandboxes = Sandbox.remote();
        process.env.MSB_BACKEND = "remote";
        for (const resource of [Sandbox, Volume, Snapshot]) assert.equal(resource.local().context.kind, "local");
        // Subsequent environment changes cannot retarget an existing collection or builder.
        process.env.MSB_API_URL = "http://127.0.0.1:" + b.address().port;
        process.env.MSB_API_KEY = "key-b";
        const builder = sandboxes.builder("task").image("python");
        const shared = remote.toBuilder().build();
        const originalId = (await sandboxes.get("task")).id;
        assert.equal((await remote.toBuilder().build().sandboxes.get("task")).id, originalId);
        assert.throws(() => remote.toBuilder().apiKey("").build());
        assert.throws(() => remote.toBuilder().url("").build());
        assert.throws(() => remote.toBuilder().requestTimeoutMs(-1).build(), RangeError);
        const derivedBuilder = remote.toBuilder().url("http://127.0.0.1:" + b.address().port).apiKey("key-b");
        remote = derivedBuilder.build();
        assert.ok(remote instanceof RemoteContext);
        assert.equal((await derivedBuilder.build().sandboxes.get("task")).id, (await remote.sandboxes.get("task")).id);
        remote = remote.toBuilder().userAgent("derived-agent").build();
        const [first, second] = await Promise.all([sandboxes.get("task"), Sandbox.ctx(remote).get("task")]);
        assert.notEqual(first.id, second.id);
        assert.equal(first.context.kind, "remote");
        assert.equal((await first.context.sandboxes.get("task")).id, first.id);
        assert.equal((await first.info()).id, first.id);
        assert.equal((await sandboxes.list()).sandboxes[0].id, first.id);
        await assert.rejects(builder.create(), /403|denied|forbidden/i);
        assert.deepEqual(requests.filter(r => r[1] === "POST").map(r => r[0]), ["a"]);
        // The environment-selected collection has no compute override. Test
        // retention separately on the context explicitly configured as shared.
        assert.equal(requests.filter(r => r[1] === "POST")[0][3], undefined);
        await assert.rejects(shared.sandboxes.builder("task").image("python").create(), /403|denied|forbidden/i);
        await assert.rejects(remote.toBuilder().computeType("standard").build().sandboxes.builder("task").image("python").create(), /403|denied|forbidden/i);
        assert.deepEqual(requests.filter(r => r[1] === "POST").map(r => r[3]), [undefined, "shared", "standard"]);
        assert.throws(() => new RemoteContext({apiKey:"key",computeType:"invalid"}));
        assert.equal(new LocalContext({home:process.env.MSB_HOME}).kind, "local");
        assert.throws(() => RemoteContext.builder().requestTimeoutMs(-1).apiKey("key").build(), RangeError);
      } finally {
        await Promise.all([a,b].map(server => new Promise(resolve => server.close(resolve))));
      }
    `], { env: { ...env, MSB_HOME: home }, encoding: "utf8", timeout: 15000 });
    expect(result.error, result.stderr).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
