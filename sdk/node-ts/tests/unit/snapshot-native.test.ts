import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { it } from "vitest";

it("returns operational Checkpoints and loads descriptor state lazily", async () => {
  const home = await mkdtemp(join(tmpdir(), "msb-snapshot-sdk-"));
  try {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
    const entry = new URL("../../dist/index.js", import.meta.url).href;
    const nativeEntry = new URL("../../native/index.cjs", import.meta.url).href;
    // A released flat descriptor also checks that lazy access keeps its original payload binding.
    const script = `
      import assert from 'node:assert/strict';
      import { mkdir, writeFile, unlink } from 'node:fs/promises';
      import { join } from 'node:path';
      const sdk = await import(${JSON.stringify(entry)});
      const native = (await import(${JSON.stringify(nativeEntry)})).default;
      const { Checkpoint } = sdk;
      assert.equal('SnapshotHandle' in sdk, false);
      assert.equal('SnapshotHandle' in native, false);
      const path = join(process.env.MSB_HOME, 'snapshots', 'fixture');
      await mkdir(path, { recursive: true });
      const descriptor = join(path, 'snapshot.json');
      const bytes = JSON.stringify({
        schema: 1, artifact: 'snapshot', scope: 'disk', created_at: '2026-05-01T12:00:00Z',
        parent: null, image: { ref: 'alpine:3.21', manifest_digest: 'sha256:' + 'a'.repeat(64) },
        source_sandbox: 'fixture', labels: {},
        state: {kind: 'file', format: 'raw', fstype: 'ext4', upper: {file: 'disk.ext4', size_bytes: 4, integrity: null}},
        extensions: {}, requires: []
      });
      await writeFile(descriptor, bytes);
      await writeFile(join(path, 'disk.ext4'), 'data');
      const opened = await Checkpoint.open(path);
      const identity = opened.id;
      await unlink(descriptor);
      const fetched = await Checkpoint.get(identity);
      const listed = (await Checkpoint.list()).find(item => item.id === identity);
      for (const resource of [opened, fetched, listed]) {
        assert.ok(resource instanceof Checkpoint);
        assert.equal(resource.id, identity);
        assert.equal(typeof resource.id, 'string');
        await assert.rejects(() => resource.state());
      }
      await writeFile(descriptor, bytes);
      for (const resource of [opened, fetched, listed]) {
        assert.equal((await resource.state()).kind, 'file');
        assert.equal((await resource.state()).upper.sizeBytes, 4n);
        assert.equal(typeof (await resource.manifest()).snapshot_id, 'string');
        await resource.verify();
      }
      await writeFile(join(path, 'metadata.json'), JSON.stringify({
        schema: 'microsandbox.snapshot-metadata/1', labels: {revision: 'new'}
      }));
      assert.deepEqual(await opened.labels(), [['revision', 'new']]);
      await listed.destroy();
      await assert.rejects(() => opened.manifest());
      assert.deepEqual(await Checkpoint.list(), []);
    `;
    await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script], {
      env: { ...env, MSB_HOME: home }, timeout: 30_000,
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 45_000);
