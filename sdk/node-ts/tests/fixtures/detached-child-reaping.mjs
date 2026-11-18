import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, readdir, readlink } from "node:fs/promises";
import { setTimeout } from "node:timers/promises";
import { Sandbox } from "../../dist/index.js";

// Linux lists children under the specific thread that spawned them.
async function children() {
  const tids = await readdir("/proc/self/task");
  const lists = await Promise.all(tids.map(async (tid) => {
    try {
      return (await readFile(`/proc/self/task/${tid}/children`, "utf8")).trim();
    } catch (error) {
      if (error.code === "ENOENT") return "";
      throw error;
    }
  }));
  return new Set(lists.flatMap((list) => list.split(/\s+/)).filter(Boolean));
}

for (const mode of ["create-detached", "detach-after-create"]) {
  const before = await children();
  const name = `reap-${randomUUID()}`;
  const detached = mode === "create-detached";
  const creator = await Sandbox.builder(name).image("alpine").cpus(1).memory(256).detached(detached).create();
  try {
    if (!detached) await creator.detach();
    const runtimes = [];
    for (const pid of await children()) {
      if (before.has(pid)) continue;
      // FD 99 is the runtime's inherited sandbox lifecycle lock.
      const lock = await readlink(`/proc/${pid}/fd/99`).catch((error) => {
        if (error.code === "ENOENT") return "";
        throw error;
      });
      if (lock.endsWith(".lock")) runtimes.push(pid);
    }
    assert.equal(runtimes.length, 1, "expected one newly created, directly owned VM");
    const [pid] = runtimes;

    // Exercise libuv child handling between creation and the independent stop.
    execFileSync(process.execPath, ["-e", ""]);
    const fetched = await Sandbox.get(name);
    await fetched.stop();
    const deadline = Date.now() + 5000;
    while ((await children()).has(pid) && Date.now() < deadline) await setTimeout(20);
    assert.equal((await children()).has(pid), false, `${mode}: child ${pid} was not reaped`);
    assert.equal(await creator.status(), "stopped"); // Keep the original wrapper alive.
    console.log(`${mode}: reaped`);
  } finally {
    await creator.destroy();
  }
}
