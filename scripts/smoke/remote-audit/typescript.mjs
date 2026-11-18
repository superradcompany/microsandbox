// Authorized opt-in remote audit. Only uniquely named test resources are mutated.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Sandbox } from "../../../sdk/node-ts/dist/sandbox.js";
import { Volume } from "../../../sdk/node-ts/dist/volume.js";
import { Snapshot } from "../../../sdk/node-ts/dist/snapshot.js";
import { RemoteContext } from "../../../sdk/node-ts/dist/context.js";
import { AuditOperations } from "./operations.mjs";
if (process.env.MSB_REMOTE_AUDIT !== "1")
  throw Error("Explicit remote audit opt-in required");
const prefix = "audit-ts-" + randomUUID().slice(0, 8),
  rows = [],
  files = mkdtempSync(join(tmpdir(), "msb-remote-audit-"));
const report = process.env.MSB_AUDIT_REPORT;
const save = () => {
  if (report)
    writeFileSync(
      report,
      JSON.stringify({ sdk: "typescript", rows }, null, 2) + "\n",
    );
};
if (report)
  writeFileSync(report + ".resources.json", JSON.stringify({ prefix }) + "\n");
function category(e) {
  const m = String(e.message);
  return /untagged enum CreateRequest/.test(m)
    ? "config_projection"
    : /not supported|unsupported|local.only|only supported by.*local|requires a local/i.test(
          m,
        )
      ? "unsupported"
      : /401/.test(m)
        ? "http_401"
        : /404|not found/i.test(m)
          ? "not_found"
          : /already running|409/i.test(m)
            ? "already_running"
            : /timeout|timed out/i.test(m)
              ? "timeout"
              : e.constructor.name;
}
const operations = new AuditOperations();
async function check(feature, fn, expect = "success", ms = 45000) {
  try {
    await operations.run(fn, ms);
    rows.push({
      feature,
      verdict: expect === "success" ? "PASS" : "FAIL",
      ...(expect === "success" ? {} : { reason: "expected_" + expect }),
    });
  } catch (e) {
    const reason = category(e);
    if (/large_bytes|ssh_exec|compact|fork|start_already/.test(feature))
      console.log(
        "DIAGNOSTIC " +
          feature +
          " " +
          String(e.message).replaceAll(process.env.MSB_API_KEY, "[redacted]"),
      );
    rows.push({
      feature,
      verdict:
        reason === "unsupported"
          ? "UNSUPPORTED"
          : expect === reason
            ? "PASS"
            : "FAIL",
      reason,
    });
  } finally {
    console.log(JSON.stringify(rows.at(-1)));
    save();
  }
  return rows.at(-1).verdict === "PASS";
}
const ctx = RemoteContext.fromEnv(),
  sandboxes = Sandbox.remote(),
  volumes = Volume.remote(),
  snapshots = Snapshot.remote();
let sb, vol, snap, restored, forked;
try {
  for (const [name, construct] of [
    [
      "constructor",
      () => new RemoteContext({ apiKey: process.env.MSB_API_KEY }),
    ],
    [
      "with_url",
      () =>
        RemoteContext.withUrl(process.env.MSB_API_URL, process.env.MSB_API_KEY),
    ],
    [
      "builder",
      () =>
        RemoteContext.builder()
          .url(process.env.MSB_API_URL)
          .apiKey(process.env.MSB_API_KEY)
          .build(),
    ],
    ["derive", () => ctx.toBuilder().userAgent("msb-remote-audit").build()],
  ])
    await check("context_" + name, async () => {
      await construct().sandboxes.list();
    });
  await check("sandbox_list", () => sandboxes.list());
  await check("volume_list", () => volumes.list());
  await check("snapshot_list", () => snapshots.list());
  await check(
    "sandbox_missing",
    () => sandboxes.get(prefix + "-missing"),
    "not_found",
  );
  await check(
    "volume_missing",
    () => volumes.get(prefix + "-missing"),
    "not_found",
  );
  await check(
    "snapshot_missing",
    () => snapshots.get(prefix + "-missing"),
    "not_found",
  );
  await check("volume_default", () => volumes.getDefault());
  if (
    await check("volume_create", async () => {
      vol = await volumes.builder(prefix).create();
    })
  ) {
    await check("volume_identity", async () => {
      assert.equal((await volumes.get(prefix)).id, vol.id);
      assert.equal(vol.context.kind, "remote");
    });
    await check("volume_info", () => vol.info());
  }
  if (
    !(await check(
      "sandbox_create",
      async () => {
        sb = await sandboxes
          .builder(prefix)
          .image("python")
          .env("AUDIT_ENV", "retained")
          .label("audit", prefix)
          .ephemeral(false)
          .create();
      },
      "success",
      240000,
    ))
  )
    throw Error("creation prerequisite failed");
  await check("sandbox_identity", async () => {
    const fetched = await sandboxes.get(prefix);
    assert.equal(fetched.id, sb.id);
    assert.equal(fetched.ownsLifecycle, false);
    await fetched[Symbol.asyncDispose]();
    assert.equal(sb.context.kind, "remote");
    assert.equal(sb.ownsLifecycle, true);
  });
  await check("sandbox_info", () => sb.info());
  await check("sandbox_status", async () =>
    assert.equal(await sb.status(), "running"),
  );
  await check("sandbox_failure_message", () => sb.lastFailureMessage());
  await check("sandbox_config", () => sb.config());
  await check("sandbox_filtered_list", async () =>
    assert.ok(
      (
        await sandboxes.listWith((b) => b.labels({ audit: prefix }).limit(1))
      ).sandboxes.some((s) => s.id === sb.id),
    ),
  );
  await check("sandbox_get_running", async () =>
    assert.equal((await sandboxes.getRunning(prefix)).id, sb.id),
  );
  await check("ensure_running_repeat", async () => {
    await sb.ensureRunning();
    await sb.ensureRunning();
  });
  await check("exec", async () =>
    assert.equal((await sb.exec("printf", ["audit-ok"])).stdout(), "audit-ok"),
  );
  await check("shell", async () =>
    assert.equal((await sb.shell('printf "$AUDIT_ENV"')).stdout(), "retained"),
  );
  await check("exec_options", async () =>
    assert.equal(
      (
        await sb.execWith("/bin/sh", (b) =>
          b
            .args(["-c", 'printf "$OVERRIDE:$PWD"'])
            .env("OVERRIDE", "set")
            .cwd("/tmp"),
        )
      ).stdout(),
      "set:/tmp",
    ),
  );
  await check("exec_nonzero_stderr", async () => {
    const o = await sb.shell("printf err >&2; exit 7");
    assert.equal(o.code, 7);
    assert.equal(o.stderr(), "err");
  });
  await check("exec_collect_repeat_wait", async () => {
    const e = await sb.shellStream("printf out; printf err >&2; exit 3");
    const o = await e.collect();
    assert.equal(o.stdout(), "out");
    assert.equal(o.stderr(), "err");
    assert.equal((await e.wait()).code, 3);
    assert.equal((await e.wait()).code, 3);
  });
  await check("exec_recv_repeat_wait", async () => {
    const e = await sb.shellStream("printf event; exit 4");
    while ((await e.recv()) !== null) {}
    assert.equal((await e.wait()).code, 4);
  });
  await check("exec_stdin", async () => {
    const e = await sb.execStreamWith("cat", (b) => b.stdinPipe());
    const input = await e.takeStdin();
    assert.ok(input);
    assert.equal(await e.takeStdin(), null);
    await input.write("input-ok");
    await input.close();
    assert.equal((await e.collect()).stdout(), "input-ok");
  });
  await check("exec_signal", async () => {
    const e = await sb.execStream("sleep", ["60"]);
    await e.signal(15);
    assert.notEqual((await e.wait()).code, 0);
  });
  await check("exec_kill", async () => {
    const e = await sb.execStream("sleep", ["60"]);
    await e.kill();
    assert.notEqual((await e.wait()).code, 0);
  });
  await check("exec_pty_resize", async () => {
    const e = await sb.execStreamWith("/bin/sh", (b) =>
      b.args(["-c", "sleep 1; stty size"]).tty(true),
    );
    await e.resize(35, 95);
    assert.match((await e.collect()).stdout(), /35 95/);
  });
  for (const [kind, fs, dir] of [
    ["sandbox", sb.fs(), "/tmp/audit"],
    ...(vol ? [["volume", vol.fs(), "audit"]] : []),
  ]) {
    await check(kind + "_fs_mkdir", () => fs.mkdir(dir));
    await check(kind + "_fs_write", () => fs.write(dir + "/a", "hello"));
    await check(kind + "_fs_read", async () =>
      assert.equal(Buffer.from(await fs.read(dir + "/a")).toString(), "hello"),
    );
    await check(kind + "_fs_read_string", async () =>
      assert.equal(await fs.readToString(dir + "/a"), "hello"),
    );
    await check(kind + "_fs_stat", async () =>
      assert.equal((await fs.stat(dir + "/a")).size, 5),
    );
    await check(kind + "_fs_list", async () =>
      assert.equal((await fs.list(dir)).length, 1),
    );
    await check(kind + "_fs_exists", async () => {
      assert.equal(await fs.exists(dir + "/a"), true);
      assert.equal(await fs.exists(dir + "/missing"), false);
    });
    await check(kind + "_fs_copy", async () => {
      await fs.copy(dir + "/a", dir + "/b");
      assert.equal(await fs.readToString(dir + "/b"), "hello");
    });
    await check(kind + "_fs_rename", async () => {
      await fs.rename(dir + "/b", dir + "/c");
      assert.equal(await fs.exists(dir + "/b"), false);
    });
    await check(kind + "_fs_write_stream", async () => {
      const w = await fs.writeStream(dir + "/stream");
      await w.write("stream-");
      await w.write("ok");
      await w.close();
    });
    await check(kind + "_fs_read_stream", async () =>
      assert.equal(
        Buffer.from(
          await (await fs.readStream(dir + "/stream")).collect(),
        ).toString(),
        "stream-ok",
      ),
    );
    await check(kind + "_fs_large_bytes", async () => {
      const payload = Buffer.alloc(2100000, 37);
      await fs.write(dir + "/large", payload);
      assert.ok(
        Buffer.from(await fs.read(dir + "/large")).equals(payload),
        "large file bytes differ",
      );
    });
    await check(kind + "_fs_remove", async () => {
      for (const f of ["a", "c", "stream", "large"])
        await fs.remove(dir + "/" + f);
    });
    await check(kind + "_fs_remove_dir", () => fs.removeDir(dir));
  }
  const local = join(files, "input");
  writeFileSync(local, "transfer-ok");
  await check("fs_upload", () => sb.fs().copyFromHost(local, "/tmp/upload"));
  await check("fs_download", async () => {
    const dest = join(files, "output");
    await sb.fs().copyToHost("/tmp/upload", dest);
    assert.equal(readFileSync(dest, "utf8"), "transfer-ok");
  });
  await check("ping", () => sb.ping());
  await check("touch", () => sb.touch());
  await check("metrics", () => sb.metrics());
  await check("logs", () => sb.logs({ tail: 5 }));
  await check("metrics_stream", async () => {
    const stream = await sb.metricsStream(1000);
    try {
      assert.ok(await stream.recv());
    } finally {
      await stream[Symbol.asyncDispose]();
    }
  });
  await check("logs_stream", async () => {
    const stream = await sb.logStream({ follow: false });
    try {
      while ((await stream.recv()) !== null) {}
    } finally {
      await stream[Symbol.asyncDispose]();
    }
  });
  await check("jobs_list", () => sb.listJobs());
  let job;
  if (
    await check("job_create", async () => {
      job = await sb.execDetached("/bin/sh", ["-c", "printf job-ok; exit 6"]);
    })
  ) {
    await check("job_wait_repeat", async () => {
      assert.equal((await job.wait()).code, 6);
      assert.equal((await job.wait()).code, 6);
    });
    await check("job_inspect", async () =>
      assert.equal((await job.inspect()).id, job.id),
    );
    await check("job_get", async () =>
      assert.equal((await sb.getJob(job.id)).id, job.id),
    );
    await check("job_logs", async () =>
      assert.ok(
        (await job.logs()).some((x) =>
          Buffer.from(x.data).toString().includes("job-ok"),
        ),
      ),
    );
    await check("job_list_filtered", async () =>
      assert.ok(
        (await sb.listJobsWith((b) => b.all(true).limit(10))).items.some(
          (j) => j.id === job.id,
        ),
      ),
    );
    await check("job_log_stream", async () => {
      const s = await job.logStream();
      try {
        while ((await s.next()) !== null) {}
      } finally {
        await s.close();
      }
    });
  }
  await check("job_attach_stdin_eof", async () => {
    const j = await sb.execDetached("cat");
    const a = await j.attach();
    try {
      await a.writeStdin(Buffer.from("job-input"));
      await j.eof();
      assert.equal((await j.wait()).code, 0);
    } finally {
      await a.detach();
      await j.kill().catch(() => {});
    }
  });
  await check("job_signal", async () => {
    const j = await sb.execDetached("sleep", ["60"]);
    try {
      await j.signal(15);
      assert.notEqual((await j.wait()).code, 0);
    } finally {
      await j.kill().catch(() => {});
    }
  });
  await check("job_kill", async () => {
    const j = await sb.execDetached("sleep", ["60"]);
    await j.kill();
    assert.notEqual((await j.wait()).code, 0);
  });
  await check("ssh_exec_sftp", async () => {
    const ssh = await sb.ssh().openClient();
    try {
      const o = await ssh.exec("printf ssh-ok");
      assert.ok(o);
      const s = await ssh.sftp();
      try {
        await s.write("/tmp/sftp", Buffer.from("sftp-ok"));
        assert.equal((await s.read("/tmp/sftp")).toString(), "sftp-ok");
      } finally {
        await s.close();
      }
    } finally {
      await ssh.close();
    }
  });
  await check("modify_dry_run", () =>
    sb.modify({ labels: { audit: prefix, modified: "yes" }, dryRun: true }),
  );
  await check("modify_labels", () =>
    sb.modify({ labels: { audit: prefix, modified: "yes" } }),
  );
  await check("storage_usage", () => sb.storageUsage(), "unsupported");
  await check("compact", () => sb.compact(), "unsupported");
  await check("pause", () => sb.pause(), "unsupported");
  await check("resume", () => sb.resume(), "unsupported");
  await check("fork", async () => {
    // Keep the child if a provider adds support, even if the capability probe
    // times out or fails its expected-unsupported verdict.
    forked = await sb.fork(prefix + "-fork");
  }, "unsupported");
  await check("detach_remote", async () => {
    await sb.detach();
    assert.equal(sb.ownsLifecycle, false);
    await sb.info();
  });
  const original = process.env.MSB_API_KEY;
  process.env.MSB_API_KEY = "invalid-audit";
  try {
    await check("retained_credentials", () => sb.info());
  } finally {
    process.env.MSB_API_KEY = original;
  }
  await check("stop", () => sb.stop(), "success", 420000);
  await check("wait_status", () => sb.waitForStatus("stopped"));
  await check("wait_stopped", () => sb.waitUntilStopped());
  if (
    await check(
      "snapshot_create",
      async () => {
        snap = await snapshots.builder(prefix).fromSandbox(prefix).create();
      },
      "success",
      240000,
    )
  ) {
    await check("snapshot_identity", async () =>
      assert.equal((await snapshots.get(snap.reference)).id, snap.id),
    );
    await check("snapshot_manifest", () => snap.manifest());
    await check("snapshot_state", () => snap.state());
    await check("snapshot_path", async () => snap.path, "unsupported");
    await check("snapshot_verify", () => snap.verify(), "unsupported");
    await check(
      "snapshot_restore",
      async () => {
        restored = await sandboxes
          .restore(snap)
          .name(prefix + "-restore")
          .restore();
      },
      "success",
      240000,
    );
    if (restored)
      await check("restored_exec", async () =>
        assert.equal(
          (await restored.shell("printf restored")).stdout(),
          "restored",
        ),
      );
  }
  await check(
    "start_detached",
    async () => {
      sb = await sandboxes.startDetached(prefix);
    },
    "success",
    240000,
  );
  await check(
    "start_already_running",
    () => sandboxes.start(prefix),
    "already_running",
  );
  await check(
    "restart",
    async () => {
      sb = await sb.restart();
    },
    "success",
    420000,
  );
  await check("kill", () => sb.kill(), "unsupported", 420000);
  await check(
    "stop_before_automatic_start",
    () => sb.stop(),
    "success",
    420000,
  );
  await check(
    "automatic_start",
    async () =>
      assert.equal((await sb.shell("printf restarted")).stdout(), "restarted"),
    "success",
    240000,
  );
} catch (e) {
  rows.push({
    feature: "prerequisites",
    verdict: "BLOCKED",
    reason: category(e),
  });
  save();
} finally {
  await operations.settle();
  for (const [feature, obj] of [
    ["fork_cleanup", forked],
    ["restore_cleanup", restored],
    ["snapshot_cleanup", snap],
    ["sandbox_cleanup", sb],
    ["volume_cleanup", vol],
  ]) {
    if (obj) await check(feature, () => obj.destroy(), "success", 420000);
    await operations.settle();
  }
  for (const [feature, c, n] of [
    ["sandbox_cleanup_verified", sandboxes, prefix],
    ["volume_cleanup_verified", volumes, prefix],
    ...(forked ? [["fork_cleanup_verified", sandboxes, prefix + "-fork"]] : []),
    ...(snap ? [["snapshot_cleanup_verified", snapshots, snap.reference]] : []),
  ])
    await check(feature, () => c.get(n), "not_found");
  rmSync(files, { recursive: true, force: true });
  save();
}
await operations.settle();
process.exitCode = rows.some(
  (r) => r.verdict === "FAIL" || r.verdict === "BLOCKED",
)
  ? 1
  : 0;
