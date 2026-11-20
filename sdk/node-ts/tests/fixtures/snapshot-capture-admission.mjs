import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtempSync, mkdirSync, symlinkSync, realpathSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

const require = createRequire(import.meta.url);
const napi = require(process.env.MSB_TEST_NATIVE_MODULE || "../../native/index.cjs");
const original = process.cwd();
const root = realpathSync(mkdtempSync(join(tmpdir(), "msb-capture-node-")));
try {
  const first = join(root, "first"), second = join(root, "second");
  mkdirSync(first); mkdirSync(second);
  mkdirSync(join(root, "target", "child"), { recursive: true });
  symlinkSync(join(root, "target", "child"), join(first, "link"), "dir");
  const handle = await napi.Sandbox.get(process.env.MSB_TEST_CAPTURE_SANDBOX);
  const running = await handle.connect();
  const destinations = [
    ["not-created/store", join(first, "not-created", "store")],
    ["link/../store", join(root, "target", "store")],
    [join(root, "absolute"), join(root, "absolute")],
  ];
  for (const [index, receiver] of [handle, running].entries()) {
    for (const [ordinal, [destDir, expected]] of destinations.entries()) {
      process.chdir(first);
      const pending = receiver.snapshot(`path-node-${index}-${ordinal}`, { destDir });
      assert.ok(pending instanceof Promise);
      process.chdir(second);
      const result = await pending;
      try {
        assert.equal(realpathSync(dirname(dirname(result.checkpoint.path))), realpathSync(expected));
        assert.ok(existsSync(join(result.checkpoint.path, "snapshot.json")));
        assert.equal(existsSync(join(second, "not-created")), false);
      } finally {
        await result.snapshot.removeGroup();
      }
    }
  }
  console.log("NODE_CAPTURE_ADMISSION_OK");
} finally {
  process.chdir(original);
  rmSync(root, { recursive: true, force: true });
}
