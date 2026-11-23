// Shared staging fixture for cross-SDK inspection checks. Only cleanup deletes it.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Sandbox } from '../../../sdk/node-ts/dist/sandbox.js';
assert.equal(process.env.MSB_REMOTE_AUDIT, '1');
const fixture = process.env.MSB_INSPECTION_FIXTURE;
const action = process.argv[2] ?? 'test';
const rows = [];
const save = () => writeFileSync(process.env.MSB_AUDIT_REPORT, JSON.stringify({ sdk: 'typescript', rows }, null, 2) + '\n');
async function check(feature, fn) {
  try { await fn(); rows.push({feature, verdict:'PASS'}); }
  catch(e) { rows.push({feature, verdict:'FAIL', reason:String(e.message).replaceAll(process.env.MSB_API_KEY,'[redacted]')}); }
  save();
}
if (action === 'setup') {
  const name = `audit-inspection-${randomUUID().slice(0,8)}`;
  writeFileSync(fixture, JSON.stringify({name}));
  const sb = await Sandbox.remote().builder(name).image('python').ephemeral(false)
    .shell('/bin/bash').entrypoint(['printf']).cmd(['configured-default']).workdir('/tmp').create();
  writeFileSync(fixture, JSON.stringify({name, id:sb.id}));
  await check('created_config', async () => {
    const c = await sb.config();
    assert.equal(c.kind, 'remote'); assert.equal(c.spec.runtime.shell, '/bin/bash');
    assert.equal(c.spec.runtime.workdir, '/tmp'); assert.ok(c.unavailable.includes('init'));
  });
} else {
  const {name,id} = JSON.parse(readFileSync(fixture,'utf8'));
  if (action === 'cleanup') {
    await check('cleanup', async () => {
      const sb = await Sandbox.remote().get(name);
      if(id) assert.equal(sb.id,id);
      await sb.destroy();
      await assert.rejects(() => Sandbox.remote().get(name),/404|not found/i);
    });
  } else {
    const sb = await Sandbox.remote().get(name); assert.equal(sb.id,id);
    let listed, cursor;
    do { const p=await Sandbox.remote().listWith(b=>cursor?b.cursor(cursor):b);
      listed=p.sandboxes.find(s=>s.id===id);cursor=p.nextCursor;
    } while(!listed && cursor);
    assert.ok(listed);
    for(const [kind, resource] of [['get',sb],['list',listed]]) {
      await check(kind+'_config', async()=> {
        const c=await resource.config(); assert.equal(c.kind,'remote');
        assert.equal(c.spec.runtime.shell,'/bin/bash'); assert.equal(c.spec.runtime.workdir,'/tmp');
        assert.deepEqual(c.spec.runtime.cmd,['configured-default']); assert.ok(c.unavailable.includes('init'));
      });
      await check(kind+'_shell',async()=>assert.equal((await resource.shell('test -n "$BASH_VERSION" && printf bash')).stdout(),'bash'));
      await check(kind+'_default_command',async()=>assert.equal((await resource.execDefault()).stdout(),'configured-default'));
      await check(kind+'_workdir',async()=>assert.equal((await resource.exec('pwd',[])).stdout().trim(),'/tmp'));
    }
    await check('sftp_workdir', async()=> {
      const ssh=await sb.ssh().openClient();
      try { const ftp=await ssh.sftp();
        try { await ftp.write('inspection-test',Buffer.from('sftp-ok'));
          assert.equal(Buffer.from(await sb.fs().read('/tmp/inspection-test')).toString(),'sftp-ok');
        } finally {await ftp.close();}
      } finally {await ssh.close();}
    });
  }
}
process.exitCode=rows.some(r=>r.verdict==='FAIL')?1:0;
