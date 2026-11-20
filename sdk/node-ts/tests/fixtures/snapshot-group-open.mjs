import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, existsSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const require = createRequire(import.meta.url);
const original = process.cwd();
const root = realpathSync(mkdtempSync(join(tmpdir(), "msb-group-open-node-")));
try {
  process.env.MSB_BACKEND = "local";
  process.env.MSB_HOME = join(root, "home");
  process.env.MSB_CONFIG_PATH = join(root, "absent.json");
  const napi = require(process.env.MSB_TEST_NATIVE_MODULE || "../../native/index.cjs");
  const first = join(root, "first"), second = join(root, "second"), target = join(root, "target");
  const external = join(target, "history"), named = join(root, "home", "snapshots", "history");
  for (const path of [first, second, join(target, "child"), external, named]) mkdirSync(path, { recursive: true });
  const metadata = '{"schema":"microsandbox.snapshot-group/1","head":null}';
  for (const path of [external, named]) writeFileSync(join(path, "group.json"), metadata);
  symlinkSync(join(target, "child"), join(first, "link"), "dir");
  let history;
  for (const selector of [external, "link/../history"]) {
    process.chdir(first);
    const pending = napi.SnapshotGroup.open(selector);
    assert.ok(pending instanceof Promise);
    process.chdir(second);
    history = await pending;
    assert.equal(history.name, "history");
    assert.equal(realpathSync(JSON.parse(await history.inspectJson()).path), external);
    assert.equal(await history.head(), null);
    assert.deepEqual(await history.checkpoints(), []);
  }
  await assert.rejects(napi.SnapshotGroup.open(""));
  await assert.rejects(napi.SnapshotGroup.open("./missing"));
  assert.ok(!existsSync(join(second, "missing")));
  const fromName = await napi.SnapshotGroup.get("history");
  assert.equal(realpathSync(JSON.parse(await fromName.inspectJson()).path), named);
  await history.removeGroup();
  assert.ok(!existsSync(external));
  assert.equal(readFileSync(join(named, "group.json"), "utf8"), metadata);
  console.log("NODE_GROUP_OPEN_OK");
} finally {
  process.chdir(original);
  rmSync(root, { recursive: true, force: true });
}
