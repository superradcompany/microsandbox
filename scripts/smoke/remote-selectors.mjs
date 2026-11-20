// Opt-in live test. MSB_API_KEY is read only by the SDK; never print credentials.
// --mutate permits disposable resources with unique names, always cleaned up in finally.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { Sandbox } from '../../sdk/node-ts/dist/sandbox.js';
import { Volume } from '../../sdk/node-ts/dist/volume.js';
import { Snapshot } from '../../sdk/node-ts/dist/snapshot.js';

if (process.env.MSB_REMOTE_SELECTOR_LIVE !== '1') throw new Error('Set MSB_REMOTE_SELECTOR_LIVE=1 to opt in');
const results = [];
const prefix = `selector-${randomUUID().slice(0, 8)}`;
// Keep an account-independent cleanup identifier if the test process is interrupted.
if (process.env.MSB_SELECTOR_REPORT && process.argv.includes('--mutate')) {
  writeFileSync(process.env.MSB_SELECTOR_REPORT + '.resources.json', JSON.stringify({ prefix }) + '\n');
}
const report = () => {
  if (process.env.MSB_SELECTOR_REPORT) writeFileSync(process.env.MSB_SELECTOR_REPORT, JSON.stringify(results, null, 2) + '\n');
};
async function check(feature, action) {
  try {
    await action();
    results.push({ feature, verdict: 'PASS' });
    console.log(JSON.stringify(results.at(-1)));
    report();
    return true;
  } catch (error) {
    const status = String(error.message).match(/\b(4\d\d|5\d\d)\b/)?.[1] ?? null;
    results.push({ feature, verdict: 'FAIL', errorType: error.constructor.name, status });
    console.log(JSON.stringify(results.at(-1)));
    report();
    return false;
  }
}
const sandboxes = Sandbox.remote(), volumes = Volume.remote(), snapshots = Snapshot.remote();
await check('sandbox_list', () => sandboxes.list());
await check('volume_list', () => volumes.list());
await check('snapshot_list', () => snapshots.list());
if (process.argv.includes('--mutate')) {
  let sandbox, volume, snapshot;
  let sandboxAttempted = false, volumeAttempted = false;
  try {
    await check('volume_create', async () => { volumeAttempted = true; volume = await volumes.builder(prefix).create(); });
    if (volume) {
      await check('volume_get_identity', async () => assert.equal((await volumes.get(prefix)).id, volume.id));
      await check('volume_live_info', async () => assert.equal((await volume.info()).id, volume.id));
      await check('volume_filesystem', async () => {
        await volume.fs().write('selector.txt', 'selector-ok');
        assert.equal(await volume.fs().readToString('selector.txt'), 'selector-ok');
      });
    }
    await check('sandbox_create', async () => {
      sandboxAttempted = true;
      sandbox = await sandboxes.builder(prefix).image('python').ephemeral(false).create();
    });
    if (sandbox) {
      await check('sandbox_get_identity', async () => assert.equal((await sandboxes.get(prefix)).id, sandbox.id));
      await check('sandbox_live_info', async () => assert.equal((await sandbox.info()).id, sandbox.id));
      await check('sandbox_live_config', () => sandbox.config());
      await check('sandbox_shell', async () => assert.equal((await sandbox.shell('printf selector-ok')).stdout(), 'selector-ok'));
      await check('sandbox_repeatable_wait', async () => {
        const execution = await sandbox.shellStream('printf selector-ok');
        const output = await execution.collect();
        assert.equal(output.stdout(), 'selector-ok');
        assert.equal((await execution.wait()).code, output.code);
        assert.equal((await execution.wait()).code, output.code);
      });
      await check('sandbox_filesystem', async () => {
        await sandbox.fs().write('/tmp/selector.txt', 'selector-ok');
        assert.equal(await sandbox.fs().readToString('/tmp/selector.txt'), 'selector-ok');
      });
      await check('sandbox_stop_then_implicit_start', async () => {
        await sandbox.stop();
        const fetched = await sandboxes.get(prefix);
        assert.equal((await fetched.shell('printf selector-ok')).stdout(), 'selector-ok');
      });
      // Bind before changing ambient credentials: neither resources nor selectors may retarget.
      const key = process.env.MSB_API_KEY;
      try {
        process.env.MSB_API_KEY = 'intentionally-invalid-selector-test';
        await check('retained_context_credentials', () => sandbox.info());
      } finally { process.env.MSB_API_KEY = key; }
      if (await check('sandbox_stop_for_snapshot', () => sandbox.stop())) {
        await check('snapshot_create', async () => { snapshot = await snapshots.builder(prefix).fromSandbox(prefix).create(); });
        if (snapshot) {
          await check('snapshot_get_identity', async () => assert.equal((await snapshots.get(snapshot.reference)).reference, snapshot.reference));
          await check('snapshot_manifest', () => snapshot.manifest());
        }
      }
    }
  } finally {
    if (snapshot) await check('snapshot_destroy', () => snapshot.destroy());
    // Handle failed create responses as well, but only for this test's unique names.
    if (sandbox) await check('sandbox_destroy', () => sandbox.destroy());
    else if (sandboxAttempted) await check('sandbox_cleanup_after_failed_create', async () => {
      try { await sandboxes.remove(prefix); } catch (e) { if (!/404|not found/i.test(String(e.message))) throw e; }
    });
    if (volume) await check('volume_destroy', () => volume.destroy());
    else if (volumeAttempted) await check('volume_cleanup_after_failed_create', async () => {
      try { await volumes.remove(prefix); } catch (e) { if (!/404|not found/i.test(String(e.message))) throw e; }
    });
    // Confirm removal through lookup without exposing other account resources.
    if (sandboxAttempted) await check('sandbox_cleanup_verified', async () => {
      let missing = false;
      try { await sandboxes.get(prefix); } catch (e) { missing = /404|not found/i.test(String(e.message)); }
      assert.ok(missing);
    });
    if (volumeAttempted) await check('volume_cleanup_verified', async () => {
      let missing = false;
      try { await volumes.get(prefix); } catch (e) { missing = /404|not found/i.test(String(e.message)); }
      assert.ok(missing);
    });
  }
}
report();
process.exitCode = results.some(result => result.verdict === 'FAIL') ? 1 : 0;
