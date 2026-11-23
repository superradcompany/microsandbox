import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

const original = process.cwd();
const root = process.argv[2];
assert.ok(root, "an isolated fixture root must be supplied by the test runner");
assert.equal(process.env.MSB_HOME, join(root, "home-a"));
try {
  const { Checkpoint, Snapshot, LocalContext } = await import("../../dist/index.js");
  const first = join(root, "first"), second = join(root, "second");
  const source = join(first, "source");
  mkdirSync(source, { recursive: true });
  mkdirSync(second);
  writeFileSync(join(source, "snapshot.json"), JSON.stringify({
    schema: 1, artifact: "snapshot", scope: "disk", created_at: "2026-05-01T12:00:00Z",
    parent: null, image: { ref: "docker.io/library/alpine:3.20", manifest_digest: `sha256:${"a".repeat(64)}` },
    source_sandbox: null,
    state: { kind: "file", format: "raw", fstype: "ext4", upper: { file: "upper.ext4", size_bytes: 512, integrity: null } },
    labels: {}, extensions: {}, requires: [],
  }));
  writeFileSync(join(source, "upper.ext4"), Buffer.alloc(512, 42));
  for (const name of ["base.tar", "delta.tar", "base-group"]) writeFileSync(join(second, name), "unrelated shadow");
  process.chdir(first);
  const firstContext = new LocalContext({ home: join(root, "home-a") });
  const secondContext = new LocalContext({ home: join(root, "home-b") });
  const checkpoint = await Checkpoint.open(source);
  await checkpoint.saveTo(join(first, "base.tar"), { plainTar: true });
  await checkpoint.saveTo(join(first, "delta.tar"), { plainTar: true, since: join(first, "base.tar") });
  await Snapshot.load("base-group", ["base.tar"]);

  // This child owns cwd and provider-home changes. Each API must resolve its omitted payload
  // from the original base, even after a same-named file shadows that group name.
  const imports = [
    () => firstContext.snapshots.load("from-group", ["delta.tar"], o => o.destDir("destination").base("base-group")),
    () => Checkpoint.loadWithOptions("delta.tar", { dest: "destination", base: "base.tar", group: "from-archive" }),
    () => Checkpoint.loadMany(["delta.tar"], { dest: "destination", base: "./base.tar", group: "from-explicit" }),
    () => Checkpoint.load("delta.tar", "destination", "base-group"),
  ];
  for (const [index, createImport] of imports.entries()) {
    process.chdir(first);
    process.env.MSB_HOME = join(root, "home-a");
    const pending = createImport();
    assert.ok(pending instanceof Promise);
    process.chdir(second);
    process.env.MSB_HOME = join(root, "home-b");
    const result = await pending;
    const handles = index === 0 ? result.checkpoints : index === 2 ? result : [result];
    assert.equal(handles.length, 1);
    const path = handles[0].path;
    assert.ok(resolve(path).startsWith(resolve(first, "destination") + "/"));
    const payloads = readdirSync(path, { recursive: true }).filter(p => p.endsWith(".raw"));
    assert.equal(payloads.length, 1);
    assert.deepEqual(readFileSync(join(path, payloads[0])), Buffer.alloc(512, 42));
    assert.deepEqual(await secondContext.snapshots.list(), []);
  }
  assert.ok(!existsSync(join(second, "destination")));
  // Native entry points must reject asynchronously, not introduce synchronous throws.
  const { napi } = await import("../../dist/internal/napi.js");
  const invalid = napi.SnapshotGroup.load("bad", [""], {});
  assert.ok(invalid instanceof Promise);
  await assert.rejects(invalid);
  const conflict = napi.SnapshotGroup.load("one", [], { group: "two" });
  assert.ok(conflict instanceof Promise);
  await assert.rejects(conflict, /different destination group/);
  console.log("NODE_IMPORT_ADMISSION_OK");
} finally {
  process.chdir(original);
}
