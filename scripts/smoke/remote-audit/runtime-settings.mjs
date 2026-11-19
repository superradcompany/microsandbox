// Opt-in regression for execution defaults retained through remote lookup.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { Sandbox } from '../../../sdk/node-ts/dist/sandbox.js';
import { AuditOperations } from './operations.mjs';

assert.equal(process.env.MSB_REMOTE_AUDIT, '1', 'Explicit remote audit opt-in required');
const report = process.env.MSB_AUDIT_REPORT;
assert.ok(report, 'MSB_AUDIT_REPORT is required');
const name = `audit-runtime-${randomUUID().slice(0, 8)}`;
writeFileSync(`${report}.resources.json`, JSON.stringify({ name }));
const operations = new AuditOperations();
const rows = [];
const save = () => writeFileSync(report, JSON.stringify({ sdk: 'typescript', rows }, null, 2) + '\n');
async function check(feature, operation) {
  try {
    await operations.run(operation, 240_000);
    rows.push({ feature, verdict: 'PASS' });
  } catch (error) {
    const reason = String(error.message).replaceAll(process.env.MSB_API_KEY, '[redacted]');
    rows.push({ feature, verdict: 'FAIL', reason });
  }
  save();
}

let created;
try {
  await check('create', async () => {
    created = await Sandbox.remote().builder(name).image('python').ephemeral(false)
      .shell('/bin/bash').entrypoint(['printf']).cmd(['configured-default'])
      .workdir('/tmp').create();
  });
  // A timeout is not cancellation. Retain any late creation before proceeding.
  await operations.settle();
  if (created) {
    const fetched = await Sandbox.remote().get(name);
    let listed, cursor;
    do {
      const page = await Sandbox.remote().listWith(b => cursor ? b.cursor(cursor) : b);
      listed = page.sandboxes.find(s => s.id === created.id);
      cursor = page.nextCursor;
    } while (!listed && cursor);
    assert.ok(listed, 'list must return the created resource');
    for (const [kind, sandbox] of [['created', created], ['fetched', fetched], ['listed', listed]]) {
      await check(`${kind}_configured_shell`, async () => {
        assert.equal((await sandbox.shell('test -n "$BASH_VERSION" && printf bash')).stdout(), 'bash');
      });
      await check(`${kind}_default_command`, async () => {
        assert.equal((await sandbox.execDefault()).stdout(), 'configured-default');
      });
      await check(`${kind}_workdir`, async () => {
        assert.equal((await sandbox.exec('pwd', [])).stdout().trim(), '/tmp');
      });
    }
  }
} finally {
  await operations.settle();
  // Recover only the exact name recorded by this invocation if the response
  // was lost; never delete another audit's resources by a shared prefix.
  if (!created) {
    try { created = await Sandbox.remote().get(name); }
    catch (error) { if (!/404|not found/i.test(error.message)) throw error; }
  }
  if (created) await check('destroy', () => created.destroy());
  await operations.settle();
  await check('cleanup_verified', () => assert.rejects(
    () => Sandbox.remote().get(name), /404|not found/i,
  ));
}
process.exitCode = rows.some(row => row.verdict === 'FAIL') ? 1 : 0;
