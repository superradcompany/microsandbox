// Follow-up probes distinguish shared defects from language-wrapper mistakes.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Sandbox } from "../../../sdk/node-ts/dist/sandbox.js";
import { Volume } from "../../../sdk/node-ts/dist/volume.js";
import { Snapshot } from "../../../sdk/node-ts/dist/snapshot.js";
import { RemoteContext } from "../../../sdk/node-ts/dist/context.js";
import { AuditOperations } from "./operations.mjs";
if (process.env.MSB_REMOTE_AUDIT !== "1") throw Error("opt-in required");
const name = "audit-probe-" + randomUUID().slice(0, 8),
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
  v = Volume.remote(),
  p = Snapshot.remote();
let sb, vol, replacement;
try {
  const remote = RemoteContext.fromEnv();
  await check(
    "derived_invalid_key_rejected",
    () =>
      remote
        .toBuilder()
        .apiKey("intentionally-invalid-audit")
        .build()
        .sandboxes.list(),
    "http_401",
  );
  await check("original_context_unchanged", () => remote.sandboxes.list());
  await check("volume_create", async () => {
    vol = await v.builder(name).create();
    await vol.fs().write("mounted", "mounted-ok");
  });
  await check("create_options_and_named_mount", async () => {
    sb = await s
      .builder(name)
      .image("python")
      .cpus(1)
      .memory(512)
      .workdir("/tmp")
      .cmd(["printf", "default-ok"])
      .ephemeral(false)
      .volume("/audit-volume", (m) => m.named(name))
      .create();
  });
  if (!sb) throw Error("creation prerequisite");
  await check("named_mount_visible", async () => {
    const o = await sb.exec("cat", ["/audit-volume/mounted"]);
    console.log(
      JSON.stringify({
        feature: "named_mount_read_diagnostic",
        code: o.code,
        stderr: o.stderr(),
      }),
    );
    assert.equal(o.stdout(), "mounted-ok");
  });
  await check("named_mount_write_persists", async () => {
    await sb.exec("/bin/sh", ["-c", "printf from-guest >/audit-volume/guest"]);
    assert.equal(await vol.fs().readToString("guest"), "from-guest");
  });
  await check("default_command", async () =>
    assert.equal((await sb.execDefault()).stdout(), "default-ok"),
  );
  await check("default_workdir", async () =>
    assert.equal((await sb.exec("pwd")).stdout(), "/tmp\n"),
  );
  const fs = sb.fs();
  for (const size of [16384, 16385, 65536, 1048576, 2100000]) {
    await check("fs_write_" + size, () =>
      fs.write("/tmp/size-" + size, Buffer.alloc(size, 37)),
    );
    await check("fs_read_" + size, async () => {
      assert.ok(
        Buffer.from(await fs.read("/tmp/size-" + size)).equals(
          Buffer.alloc(size, 37),
        ),
        "file bytes differ",
      );
    });
  }
  await check("guest_generate_large_file", async () =>
    assert.equal(
      (
        await sb.exec("python", [
          "-c",
          "open('/tmp/generated','wb').write(b'Q'*2100000)",
        ])
      ).code,
      0,
    ),
  );
  await check("large_read_stream", async () =>
    assert.ok(
      Buffer.from(
        await (await fs.readStream("/tmp/generated")).collect(),
      ).equals(Buffer.alloc(2100000, 81)),
      "stream bytes differ",
    ),
  );
  await check("large_write_stream_64k_chunks", async () => {
    const w = await fs.writeStream("/tmp/streamed");
    try {
      for (let i = 0; i < 32; i++) await w.write(Buffer.alloc(65536, 37));
    } finally {
      await w.close();
    }
    assert.ok(
      Buffer.from(await fs.read("/tmp/streamed")).equals(
        Buffer.alloc(2097152, 37),
      ),
      "streamed file differs",
    );
  });
  await check("large_exec_output", async () => {
    const o = await sb.exec("python", [
      "-c",
      "import sys; sys.stdout.write('x'*1048576)",
    ]);
    assert.equal(o.stdout().length, 1048576);
  });
  await check("ssh_exec_without_sftp", async () => {
    const ssh = await sb.ssh().openClient({ sftp: false });
    try {
      const o = await ssh.exec("printf ssh-ok");
      assert.equal(o.stdout.toString(), "ssh-ok");
    } finally {
      await ssh.close();
    }
  });
  await check("ssh_default_client_open", async () => {
    const ssh = await sb.ssh().openClient();
    await ssh.close();
  });
  await check(
    "exec_timeout",
    () => sb.execWith("sleep", (b) => b.args(["10"]).timeout(100)),
    "timeout",
  );
  await check("stop_for_nonstarting_inspection", () => sb.stop());
  await check("inspection_does_not_start", async () => {
    assert.equal(await sb.status(), "stopped");
    await sb.info();
    try {
      await sb.config();
    } catch (e) {
      if (!String(e.message).includes("untagged enum CreateRequest")) throw e;
    }
    assert.equal(await sb.status(), "stopped");
  });
  await check(
    "snapshot_full_rejected",
    async () => {
      const x = await p
        .builder(name + "-full")
        .fromSandbox(name)
        .full()
        .create();
      await x.destroy();
    },
    "unsupported",
  );
  await check(
    "snapshot_group_rejected",
    async () => {
      const x = await p
        .builder(name + "-group")
        .fromSandbox(name)
        .group(name)
        .create();
      await x.destroy();
    },
    "unsupported",
  );
  await check("destroy_original", () => sb.destroy());
  await check("recreate_same_name", async () => {
    replacement = await s
      .builder(name)
      .image("python")
      .ephemeral(false)
      .create();
    assert.notEqual(replacement.id, sb.id);
  });
  await check(
    "stale_identity_inspection_rejected",
    () => sb.info(),
    "not_found",
  );
  await check(
    "stale_identity_execution_rejected",
    () => sb.shell("true"),
    "not_found",
  );
  await check(
    "stale_identity_destroy_rejected",
    () => sb.destroy(),
    "not_found",
  );
  await check("replacement_still_usable", async () =>
    assert.equal((await replacement.shell("printf alive")).stdout(), "alive"),
  );
} finally {
  await operations.settle();
  if (replacement)
    await check("replacement_cleanup", () => replacement.destroy());
  else if (sb) await check("sandbox_cleanup", () => sb.destroy());
  await operations.settle();
  if (vol) await check("volume_cleanup", () => vol.destroy());
  await operations.settle();
  await check("sandbox_cleanup_verified", () => s.get(name), "not_found");
  await check("volume_cleanup_verified", () => v.get(name), "not_found");
}

await operations.settle();
process.exitCode = rows.some((r) => r.verdict === "FAIL") ? 1 : 0;
