import { expect, it } from "vitest";
import { Sandbox, Snapshot } from "../dist/index.js";

// Opt-in because this starts real VMs with a matching development runtime/kernel bundle.
it.skipIf(process.env.MSB_COW_LIVE !== "1")("captures a resident pause and restores private memory", async () => {
  const name = `cow8-node-${process.pid}`;
  const source = await Sandbox.builder(name).image("alpine").rootDisk(512).memory(256).create();
  let child: Sandbox | undefined;
  const branches: Sandbox[] = [];
  try {
    await source.exec("sh", ["-c", "echo source > /dev/shm/sdk-marker"]);
    await source.pause();
    const paused = await Sandbox.get(name);
    expect(paused.status).toBe("paused");
    const branched = await paused.branch(`${name}-paused-branch`);
    branches.push(branched);
    expect((await branched.exec("cat", ["/dev/shm/sdk-marker"])).stdout().trim()).toBe("source");
    const snapshot = await Snapshot.builder(`${name}-full`).fromSandbox(name).full().create();
    await paused.resume();
    child = await Sandbox.restore(snapshot.path).name(`${name}-child`).forked().restore();
    expect((await child.exec("cat", ["/dev/shm/sdk-marker"])).stdout().trim()).toBe("source");
    await child.exec("sh", ["-c", "echo child > /dev/shm/sdk-marker"]);
    const descendant = await child.branch(`${name}-branch`);
    branches.push(descendant);
    expect((await descendant.exec("cat", ["/dev/shm/sdk-marker"])).stdout().trim()).toBe("child");
    expect((await source.exec("cat", ["/dev/shm/sdk-marker"])).stdout().trim()).toBe("source");
    await child.pause();
    await child.resume();
  } finally {
    // A paused VM cannot stop gracefully. Attempt every cleanup even when one
    // fails so an assertion or cleanup error does not strand sibling VMs.
    const results = await Promise.allSettled([...branches, ...(child ? [child] : []), source].map(async (sandbox) => {
      if ((await Sandbox.get(sandbox.name)).status === "paused") await sandbox.resume();
      await sandbox.stop();
    }));
    for (const result of results) if (result.status === "rejected") throw result.reason;
  }
}, 120_000);

it.skipIf(process.env.MSB_BATCH_LIVE !== "1")("branches one capture through both SDK surfaces", async () => {
  const name = `batch-node-${process.pid}`;
  const source = await Sandbox.builder(name).image("mirror.gcr.io/library/alpine:3.20").rootDisk(512).memory(256).create();
  const children: Sandbox[] = [];
  try {
    await source.exec("sh", ["-c", "echo original > /dev/shm/batch-marker"]);
    for (const target of [source, await Sandbox.get(name)]) {
      const names = [0, 1].map(i => `${name}-${children.length}-${i}`);
      const outcomes = await target.branchMany(names);
      for (const outcome of outcomes) if (outcome.sandbox) children.push(outcome.sandbox);
      expect(outcomes.map(o => o.name)).toEqual(names);
      for (const outcome of outcomes) {
        expect(outcome.error).toBeUndefined();
        expect((await outcome.sandbox!.exec("cat", ["/dev/shm/batch-marker"])).stdout().trim()).toBe("original");
      }
    }
    await children[0]!.exec("sh", ["-c", "echo private > /dev/shm/batch-marker"]);
    expect((await children[1]!.exec("cat", ["/dev/shm/batch-marker"])).stdout().trim()).toBe("original");
    await expect(source.branchMany([])).rejects.toThrow();
    await expect(source.branchMany([name + "-dup", name + "-dup"])).rejects.toThrow();
  } finally {
    const results = await Promise.allSettled([...children, source].map(s => s.stop()));
    for (const result of results) if (result.status === "rejected") throw result.reason;
  }
}, 120_000);
