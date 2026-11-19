// Follow-up probes distinguish shared defects from language-wrapper mistakes.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Sandbox } from "../../../sdk/node-ts/dist/sandbox.js";
import { Volume } from "../../../sdk/node-ts/dist/volume.js";
import { AuditOperations } from "./operations.mjs";
if (process.env.MSB_REMOTE_AUDIT !== "1") throw Error("opt-in required");
const name = "audit-perm-" + randomUUID().slice(0, 8),
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
let strict, relaxed, vol;
try {
  await check("volume_create", async () => {
    vol = await v.builder(name).create();
    await vol.fs().write("api-file", "api-data");
  });
  await check("strict_mount_create", async () => {
    strict = await s
      .builder(name)
      .image("python")
      .ephemeral(false)
      .volume("/audit", (m) => m.named(name))
      .create();
  });
  async function read(resource, file) {
    const o = await resource.exec("cat", ["/audit/" + file]);
    console.log(
      JSON.stringify({
        feature: "read_diagnostic",
        file,
        code: o.code,
        stderr: o.stderr(),
      }),
    );
    assert.equal(o.code, 0);
    return o.stdout();
  }
  await check("strict_reads_api_upload", async () =>
    assert.equal(await read(strict, "api-file"), "api-data"),
  );
  await check("guest_create", async () => {
    const o = await strict.exec("/bin/sh", [
      "-c",
      "printf guest-data >/audit/guest-file",
    ]);
    assert.equal(o.code, 0);
    assert.equal(await read(strict, "guest-file"), "guest-data");
  });
  await check("api_overwrite_guest_file", () =>
    vol.fs().write("guest-file", "replacement"),
  );
  await check("strict_reads_api_replacement", async () =>
    assert.equal(await read(strict, "guest-file"), "replacement"),
  );
  await check("relaxed_mount_create", async () => {
    relaxed = await s
      .builder(name + "-relaxed")
      .image("python")
      .ephemeral(false)
      .volume("/audit", (m) => m.named(name).statVirtualization("relaxed"))
      .create();
  });
  if (relaxed) {
    await check("relaxed_reads_api_upload", async () =>
      assert.equal(await read(relaxed, "api-file"), "api-data"),
    );
    await check("relaxed_reads_api_replacement", async () =>
      assert.equal(await read(relaxed, "guest-file"), "replacement"),
    );
  }
} finally {
  await operations.settle();
  for (const [label, resource] of [
    ["relaxed", relaxed],
    ["strict", strict],
    ["volume", vol],
  ]) {
    if (resource) await check(label + "_cleanup", () => resource.destroy());
    // A timed-out sandbox deletion must finish before deleting its volume.
    await operations.settle();
  }
  await check("strict_cleanup_verified", () => s.get(name), "not_found");
  await check(
    "relaxed_cleanup_verified",
    () => s.get(name + "-relaxed"),
    "not_found",
  );
  await check("volume_cleanup_verified", () => v.get(name), "not_found");
}

await operations.settle();
process.exitCode = rows.some((r) => r.verdict === "FAIL") ? 1 : 0;
