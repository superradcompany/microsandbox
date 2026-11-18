import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("captures storage backends at invocation and preserves native bigint reports", () => {
  const home = mkdtempSync(join(tmpdir(), "msb-storage-native-"));
  // Isolate process-global backend/config caches before importing the addon. The
  // prune calls can only reach this test's temporary files and never start a VM.
  const env: NodeJS.ProcessEnv = {
    ...process.env, MSB_HOME: home, MSB_CONFIG_PATH: join(home, "config.json"),
  };
  delete env.MSB_PROFILE;
  delete env.MSB_BACKEND;
  const script = `
    import assert from "node:assert/strict";
    import { mkdirSync, writeFileSync, existsSync } from "node:fs";
    import { join } from "node:path";
    import { Storage } from "./dist/storage.js";
    import { Snapshot } from "./dist/snapshot.js";
    import { setDefaultBackend } from "./dist/runtime.js";
    import { UnsupportedError } from "./dist/errors.js";

    const cloud = { kind: "cloud", url: "http://127.0.0.1:9", apiKey: "test" };
    setDefaultBackend("local");
    const dir = join(process.env.MSB_HOME, "cache", "memory", "branches");
    mkdirSync(dir, { recursive: true });
    const backing = join(dir, "branch_fixture-4096.ram");
    const lock = join(dir, "branch_fixture-4096.handoff-lock");
    writeFileSync(backing, Buffer.alloc(8192));
    writeFileSync(lock, "");

    const observing = Storage.usage();
    setDefaultBackend(cloud);
    const observed = await observing;
    assert.equal(observed.branchMemory.count, 1);
    assert.equal(observed.branchMemory.logicalBytes, 8192n);
    assert.equal(observed.images.inUse, null);

    setDefaultBackend("local");
    const previewing = Storage.prune({ dryRun: true });
    setDefaultBackend(cloud);
    const preview = await previewing;
    assert.equal(preview.filesRemoved, 0);
    assert.equal(preview.logicalBytesRemoved, 0n);
    assert.equal(preview.entries[0].logicalBytes, 8192n);
    assert.equal(preview.entries[0].state, "reclaimable");
    assert(existsSync(backing));

    // Conversely a cloud invocation must never become local deletion merely
    // because the default changes before the native future is polled.
    const refused = Storage.prune();
    setDefaultBackend("local");
    await assert.rejects(refused, UnsupportedError);
    assert(existsSync(backing));

    const pruning = Storage.prune();
    setDefaultBackend(cloud);
    const result = await pruning;
    assert.equal(result.filesRemoved, 1);
    assert.equal(result.logicalBytesRemoved, 8192n);
    assert.equal(result.physicalBytesReclaimed, null);
    assert.equal(result.entries[0].state, "removed");
    assert(!existsSync(backing));
    assert(existsSync(lock));

    setDefaultBackend("local");
    const snapshotDir = join(process.env.MSB_HOME, "fixture-snapshot");
    mkdirSync(snapshotDir);
    const manifest = JSON.stringify({
      schema: 1, artifact: "snapshot", scope: "disk",
      created_at: "2026-05-01T12:00:00Z", parent: null,
      image: { ref: "docker.io/library/alpine:3.20", manifest_digest: "sha256:" + "a".repeat(64) },
      source_sandbox: null,
      state: { kind: "file", format: "raw", fstype: "ext4",
        upper: { file: "upper.ext4", size_bytes: 5, integrity: null } },
      labels: {}, extensions: {}, requires: [],
    });
    writeFileSync(join(snapshotDir, "snapshot.json"), manifest);
    writeFileSync(join(snapshotDir, "upper.ext4"), "hello");
    const artifact = await Snapshot.open(snapshotDir);
    setDefaultBackend(cloud);
    const item = await artifact.storageUsage();
    assert.equal(item.path, snapshotDir);
    assert.equal(item.logicalBytes, BigInt(Buffer.byteLength(manifest)) + 5n);
    assert.equal(item.reclaimable, null);
  `;
  try {
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      env,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(child.error, child.stderr).toBeUndefined();
    expect(child.status, child.stdout + child.stderr).toBe(0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
