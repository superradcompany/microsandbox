#!/usr/bin/env node
/** PTY completion regression against an explicitly selected disposable local home. */
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';

assert(process.env.MSB_HOME, 'set an isolated MSB_HOME');
assert.equal(process.env.MSB_BACKEND, 'local', 'this test creates local VMs only');
const { Sandbox, setDefaultBackend } = await import(
  process.env.MSB_TEST_SDK ?? new URL('../../sdk/node-ts/dist/index.js', import.meta.url).href
);
// Also exercise the released SDK when MSB_TEST_SDK points to its installed package.
setDefaultBackend?.('local');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function deadline(promise, ms) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('job completion timed out')), ms);
    })]);
  } finally { clearTimeout(timer); }
}

const sandbox = await Sandbox.builder(`pty-exit-${process.pid}`)
  .image(process.env.MSB_TEST_IMAGE ?? 'alpine:3.22').cpus(2).memory(512).create();
try {
  for (const kill of [false, true]) {
    for (let iteration = 0; iteration < 10; iteration++) {
      const pidfile = `/tmp/pty-child-${kill}-${iteration}`;
      const marker = '<FINAL_OUTPUT>';
      const command = `trap '' HUP; setsid sh -c 'trap "" HUP; echo $$ > ${pidfile}; exec sleep 60' & `
        + `while [ ! -s ${pidfile} ]; do sleep .01; done; `
        + `head -c 262144 /dev/zero | tr '\\000' x; printf '${marker}'; `
        + (kill ? 'while :; do sleep 1; done' : 'exit 7');
      const job = await sandbox.execDetachedWith('/bin/sh', b => b.args(['-c', command]).tty(true).stdinPipe());
      if (kill) {
        // Signal only after the leader has written its final marker; the separate
        // background process group must survive both job.kill and completion.
        const readyBy = performance.now() + 5000;
        while (!Buffer.concat((await job.logs()).map(entry => entry.data)).includes(Buffer.from(marker))) {
          assert(performance.now() < readyBy, 'leader did not write final marker');
          await pause(10);
        }
        await job.kill();
      }
      const started = performance.now();
      const outcome = await deadline(job.wait(), 5000);
      assert.equal(outcome.code, kill ? -1 : 7);
      assert.deepEqual(await deadline(job.wait(), 1000), outcome);
      const info = await job.inspect();
      assert.equal(info.state, 'exited');
      assert.equal(info.exitCode, outcome.code);
      const output = Buffer.concat((await job.logs()).map(entry => entry.data));
      assert.deepEqual(output, Buffer.concat([Buffer.alloc(262144, 'x'), Buffer.from(marker)]));
      // /proc existence alone would accept a zombie. Require a live sleep process.
      const child = await sandbox.shell(`pid=$(cat ${pidfile}); kill -0 "$pid" && ! grep -q ') Z ' /proc/$pid/stat`);
      assert.equal(child.code, 0, 'background child did not survive completion');
      console.log(JSON.stringify({scenario: kill ? 'job.kill' : 'normal exit', iteration,
        code: outcome.code, bytes: output.length, childAlive: true,
        completionMs: Math.round(performance.now() - started)}));
      // This is test teardown, never part of the completion implementation.
      assert.equal((await sandbox.shell(`kill -KILL $(cat ${pidfile}); rm ${pidfile}`)).code, 0);
    }
  }
} finally {
  await sandbox.destroy();
  console.log('Destroyed disposable PTY test sandbox');
}
