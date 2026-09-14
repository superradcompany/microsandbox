import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { napi } from "../../dist/internal/napi.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function snapshotFixture() {
  const path = await mkdtemp(join(tmpdir(), "msb-copy-native-"));
  directories.push(path);
  const manifest = JSON.stringify({
    schema: 1,
    artifact: "snapshot",
    scope: "disk",
    created_at: "2026-05-01T12:00:00Z",
    parent: null,
    image: {
      ref: "docker.io/library/alpine:3.20",
      manifest_digest: `sha256:${"a".repeat(64)}`,
    },
    source_sandbox: null,
    state: {
      kind: "file", format: "raw", fstype: "ext4",
      upper: { file: "upper.ext4", size_bytes: 5, integrity: null },
    },
    labels: {}, extensions: {}, requires: [],
  });
  await writeFile(join(path, "snapshot.json"), manifest);
  // Archive copying treats the disk as opaque bytes; no running VM is needed.
  await writeFile(join(path, "upper.ext4"), "hello");
  return { path, manifest, snapshot: await napi.Snapshot.open(path) };
}

describe("native snapshot copy ownership", () => {
  it("consumes the builder before returning its save promise", async () => {
    const { path, manifest, snapshot } = await snapshotFixture();
    expect(snapshot.path).toBe(path);
    expect(snapshot.reference).toBe(path);
    const output = join(path, "copy.tar.zst");
    const builder = snapshot.copyTo(output);
    const saving = builder.save();
    expect(saving).toBeInstanceOf(Promise);
    expect(() => builder.labels({ late: "mutation" })).toThrow("already consumed");
    expect(() => builder.recordIntegrity(true)).toThrow("already consumed");
    const secondSave = builder.save();
    expect(secondSave).toBeInstanceOf(Promise);
    await expect(secondSave).rejects.toThrow("already consumed");
    await saving;
    expect((await stat(output)).size).toBeGreaterThan(0);
    expect(await readFile(join(path, "snapshot.json"), "utf8")).toBe(manifest);
    expect(await readFile(join(path, "upper.ext4"), "utf8")).toBe("hello");
  });

  it("saves after the JavaScript builder reference is released", async () => {
    const { path, snapshot } = await snapshotFixture();
    const output = join(path, "detached.tar.zst");
    const saving = snapshot.copyTo(output).save();
    globalThis.gc?.();
    await saving;
    expect((await stat(output)).size).toBeGreaterThan(0);
  });
});
