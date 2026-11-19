import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";

it("returns operational Volumes from create/get/list and protects same-name replacements", async () => {
  const home = await mkdtemp(join(tmpdir(), "msb-volume-sdk-"));
  try {
    // Isolate native configuration initialization from other tests and the user's home.
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("MSB_")));
    const entry = new URL("../../dist/index.js", import.meta.url).href;
    const nativeEntry = new URL("../../native/index.cjs", import.meta.url).href;
    const script = `
      import assert from 'node:assert/strict';
      const sdk = await import(${JSON.stringify(entry)});
      const { Volume } = sdk;
      assert.equal('VolumeHandle' in sdk, false);
      const native = (await import(${JSON.stringify(nativeEntry)})).default;
      assert.equal('VolumeHandle' in native, false);
      const created = await Volume.builder('cache').label('team', 'sdk').create();
      const fetched = await Volume.get('cache');
      const [listed] = await Volume.list();
      for (const resource of [created, fetched, listed]) {
        assert.ok(resource instanceof Volume);
        assert.equal(resource.id, created.id);
        assert.equal(typeof resource.id, 'string');
        assert.equal(resource.name, 'cache');
        assert.equal(resource.kind, 'dir');
        assert.equal((await resource.info()).kind, resource.kind);
        assert.deepEqual((await resource.info()).labels, [['team', 'sdk']]);
        await resource.fs().write('marker', Buffer.from('original'));
      }
      const disk = await Volume.builder('disk').disk().size(256).create();
      try {
        assert.equal(disk.kind, 'disk');
        assert.equal((await disk.info()).kind, disk.kind);
      } finally { await disk.destroy(); }
      const retainedFs = listed.fs();
      await listed.destroy();
      const replacement = await Volume.builder('cache').create();
      assert.notEqual(replacement.id, created.id);
      await replacement.fs().write('marker', Buffer.from('replacement'));
      await assert.rejects(() => created.destroy());
      await assert.rejects(() => retainedFs.write('marker', Buffer.from('wrong')));
      assert.equal(await replacement.fs().readToString('marker'), 'replacement');
      await Volume.remove('cache');
      assert.deepEqual(await Volume.list(), []);
    `;
    const { stderr } = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script], {
      env: { ...env, MSB_HOME: home }, timeout: 30_000,
    });
    expect(stderr).not.toContain("AssertionError");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 45_000);
