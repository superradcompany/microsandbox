// Follow-up probes distinguish shared defects from language-wrapper mistakes.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Sandbox } from "../../../sdk/node-ts/dist/sandbox.js";
import { Volume } from "../../../sdk/node-ts/dist/volume.js";
import { AuditOperations } from "./operations.mjs";
if (process.env.MSB_REMOTE_AUDIT !== "1") throw Error("opt-in required");
const name = "audit-caps-" + randomUUID().slice(0, 8),
  rows = [],
  report = process.env.MSB_AUDIT_REPORT;
writeFileSync(report + ".resources.json", JSON.stringify({ prefix: name }));
const operations = new AuditOperations();
async function check(feature, fn, expected = "success") {
  try {
    await operations.run(fn, 90000);
    rows.push({ feature, verdict: expected === "success" ? "PASS" : "FAIL" });
  } catch (e) {
    const message = String(e.message).replaceAll(
      process.env.MSB_API_KEY,
      "[redacted]",
    );
    const reason = /untagged enum CreateRequest/.test(message)
      ? "config_projection"
      : /channel closed/.test(message)
        ? "channel_closed"
        : /not supported|unsupported|requires a local|only supported by.*local/i.test(
              message,
            )
          ? "unsupported"
          : /401/.test(message)
            ? "http_401"
            : /404|not found|identity.*changed|replaced/i.test(message)
              ? "not_found"
              : /timeout|timed out/i.test(message)
                ? "timeout"
                : e.constructor.name;
    rows.push({
      feature,
      verdict:
        reason === "unsupported"
          ? "UNSUPPORTED"
          : reason === expected
            ? "PASS"
            : "FAIL",
      reason,
    });
    console.log("DIAGNOSTIC " + feature + " " + message);
  }
  console.log(JSON.stringify(rows.at(-1)));
  writeFileSync(
    report,
    JSON.stringify({ sdk: "typescript-probes", rows }, null, 2),
  );
}
const s = Sandbox.remote(),
  v = Volume.remote();
let sb, isolated;
const extras = [];
try {
  await check("creation_progress", async () => {
    const c = await s
      .builder(name)
      .image("python")
      .ephemeral(false)
      .createWithProgress();
    const events = [];
    const reader = (async () => {
      for await (const event of c.progress) events.push(event.kind);
    })();
    sb = await c.awaitSandbox();
    await reader;
    console.log(
      JSON.stringify({
        feature: "progress_events_observed",
        count: events.length,
      }),
    );
  });
  if (!sb) throw Error("creation prerequisite failed");
  await check("sandbox_config", () => sb.config());
  await check("ssh_exec", async () => {
    const ssh = await sb.ssh().openClient({ sftp: false });
    try {
      assert.equal(
        (await ssh.exec("printf ssh-ok")).stdout.toString(),
        "ssh-ok",
      );
    } finally {
      await ssh.close();
    }
  });
  await check("sftp_read_write", async () => {
    const ssh = await sb.ssh().openClient();
    try {
      const ftp = await ssh.sftp();
      try {
        await ftp.write("/tmp/sftp", Buffer.from("sftp"));
        assert.equal((await ftp.read("/tmp/sftp")).toString(), "sftp");
      } finally {
        await ftp.close();
      }
    } finally {
      await ssh.close();
    }
  });
  await check("logs_follow", async () => {
    const stream = await sb.logStream({ follow: true, sources: ["all"] });
    try {
      const entry = await stream.recv();
      assert.ok(entry);
      assert.ok(entry.cursor);
    } finally {
      await stream[Symbol.asyncDispose]();
    }
  });
  await check("network_dns_https", async () => {
    const out = await sb.exec("python", [
      "-c",
      "import urllib.request; print(urllib.request.urlopen('https://example.com',timeout=10).status)",
    ]);
    assert.equal(out.code, 0);
    assert.equal(out.stdout().trim(), "200");
  });
  await check("create_network_disabled", async () => {
    isolated = await s
      .builder(name + "-offline")
      .image("python")
      .ephemeral(false)
      .disableNetwork()
      .create();
  });
  if (isolated)
    await check("network_disabled_enforced", async () => {
      const out = await isolated.exec("python", [
        "-c",
        "import socket; s=socket.socket(); s.settimeout(2); r=s.connect_ex(('1.1.1.1',443)); print(r); raise SystemExit(0 if r else 1)",
      ]);
      assert.equal(out.code, 0);
    });
  for (const [feature, configure] of [
    ["nested_virtualization", (b) => b.nestedVirt(true)],
    ["host_port", (b) => b.port(54321, 80)],
    [
      "host_bind",
      (b) => b.volume("/audit-bind", (m) => m.bind("/" + name + "-bind")),
    ],
    ["inline_owned_volume", (b) => b.volume("/audit-owned", (m) => m.owned())],
  ])
    await check(
      feature === "host_bind" ? "provider_bind_creation" : "reject_" + feature,
      async () => {
        const made = await configure(
          s
            .builder(name + "-" + feature)
            .image("python")
            .ephemeral(false),
        ).create();
        extras.push(made);
      },
      feature === "host_bind" ? "success" : "unsupported",
    );
} finally {
  await operations.settle();
  for (const resource of [...extras, isolated, sb].filter(Boolean)) {
    await check("cleanup_" + resource.name, () => resource.destroy());
    await operations.settle();
  }
  await check("bind_directory_cleanup", async () => {
    const d = await v.getDefault();
    if (await d.fs().exists(name + "-bind")) {
      assert.equal((await d.fs().list(name + "-bind")).length, 0);
      await d.fs().removeDir(name + "-bind");
    }
  });
  await operations.settle();
  await check("cleanup_verified", () => s.get(name), "not_found");
  if (isolated)
    await check(
      "offline_cleanup_verified",
      () => s.get(name + "-offline"),
      "not_found",
    );
}

await operations.settle();
process.exitCode = rows.some((r) => r.verdict === "FAIL") ? 1 : 0;
