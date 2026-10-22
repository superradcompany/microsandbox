import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const original = process.cwd();
const root = realpathSync(mkdtempSync(join(tmpdir(), "msb-import-node-")));
try {
  process.env.MSB_HOME = join(root, "home-a");
  process.env.MSB_CONFIG_PATH = join(root, "absent.json");
  const { Checkpoint, Snapshot, setDefaultBackend } = await import("../../dist/index.js");
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
  setDefaultBackend("local");
  const checkpoint = await Checkpoint.open(source);
  await checkpoint.saveTo(join(first, "base.tar"), { plainTar: true });
  await checkpoint.saveTo(join(first, "delta.tar"), { plainTar: true, since: join(first, "base.tar") });
  await Snapshot.load("base-group", ["base.tar"]);

  // This child owns cwd/backend changes. Each import must resolve its omitted payload
  // from the original base, even after a same-named file shadows that group name.
  for (let index = 0; index < 16; index++) {
    process.chdir(first);
    process.env.MSB_HOME = join(root, "home-a");
    setDefaultBackend("local");
    const base = ["base-group", "base.tar", "./base.tar"][index % 3];
    let pending;
    if (index % 4 === 0) pending = Snapshot.loadWith(`group-${index}`, ["delta.tar"], o => o.destDir("destination").base(base));
    else if (index % 4 === 1) pending = Checkpoint.loadWithOptions("delta.tar", { dest: "destination", base, group: `group-${index}` });
    else if (index % 4 === 2) pending = Checkpoint.loadMany(["delta.tar"], { dest: "destination", base, group: `group-${index}` });
    else pending = Checkpoint.load("delta.tar", "destination", base);
    assert.ok(pending instanceof Promise);
    process.chdir(second);
    process.env.MSB_HOME = join(root, "home-b");
    setDefaultBackend("local");
    const result = await pending;
    const handles = index % 4 === 0 ? result.checkpoints : index % 4 === 2 ? result : [result];
    assert.equal(handles.length, 1);
    const path = handles[0].path;
    assert.ok(resolve(path).startsWith(resolve(first, "destination") + "/"));
    const payloads = readdirSync(path, { recursive: true }).filter(p => p.endsWith(".raw"));
    assert.equal(payloads.length, 1);
    assert.deepEqual(readFileSync(join(path, payloads[0])), Buffer.alloc(512, 42));
    assert.deepEqual(await Snapshot.list(), []);
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
  rmSync(root, { recursive: true, force: true });
}
