const { Sandbox, Snapshot } = await import(process.env.SDK_MODULE ?? '../../../sdk/node-ts/dist/index.js');
import { mkdir } from 'node:fs/promises';
const prefix = process.env.QUAL_SOURCE ?? 'compact-flat';
const out = process.env.QUAL_ROOT;
await mkdir(out, {recursive:true});
async function measure(test, call) {
  const start = performance.now(); const result = await call();
  console.log(JSON.stringify({test,ms:performance.now()-start,result:result?.inputLayers !== undefined ? result : 'PASS'})); return result;
}
const handle = await Sandbox.get(prefix);
await measure('node-plan', () => handle.compact({dryRun:true}));
for (const layers of [1, -1, 2.5, NaN, Infinity, 4294967296]) {
  let rejected = false;
  try { await handle.compact({layers, dryRun:true}); } catch { rejected = true; }
  if (!rejected) throw new Error(`accepted invalid count ${layers}`);
}
await measure('node-stopped-compact', () => handle.compact());
await measure('node-save-since', () => Snapshot.save(prefix+'-4',out+'/delta.tar.zst',{since:prefix+'-2'}));
await measure('node-save-last', () => Snapshot.save(prefix+'-4',out+'/last.tar',{lastLayers:2,plainTar:true}));
await measure('node-load-base', () => Snapshot.load(out+'/delta.tar.zst',out+'/imported',prefix+'-2'));
for (const disk of [false,true]) {
  let child;
  try {
    let builder = Sandbox.builder('compact-node-'+(disk?'disk':'full')).fromSnapshot(out+'/delta.tar.zst').snapshotBase(prefix+'-2');
    if (disk) builder = builder.diskOnly();
    child = await measure('node-restore-'+disk, () => builder.create());
    const data = await child.exec('sh',['-c','sha256sum -c /expected && test $(cat /version) = 4']);
    if (data.code !== 0) throw new Error(data.stderr());
    await measure('node-online-compact-'+disk, () => child.compact({layers:3}));
    const check = await child.exec('sh',['-c','sha256sum -c /expected']);
    if (check.code !== 0) throw new Error(check.stderr());
  } finally { if (child) await child.stop(); }
}
