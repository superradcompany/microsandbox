import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LocalContext, Sandbox, Volume } from "../dist/index.js";
import { msbPath } from "../dist/internal/resolve-binary.js";

describe.skipIf(!msbPath())("revamp real-runtime contracts", () => {
  const name = `sdk-revamp-contract-${process.pid}`;
  let sb: Sandbox;

  beforeAll(async () => {
    sb = await Sandbox.builder(name).image("alpine").cpus(1).memory(512).create();
  });

  afterAll(async () => {
    await sb?.stop().catch(() => undefined);
    await Sandbox.remove(name).catch(() => undefined);
  });

  for (const observation of ["wait", "collect", "recv"] as const) {
    for (const code of [0, 7]) {
      it(`retains completion after ${observation}, exit ${code}`, async () => {
        const marker = `/tmp/runs-${observation}-${code}`;
        const execution = await sb.shellStream(`echo ran >> ${marker}; printf output; exit ${code}`);
        if (observation === "collect") {
          const output = await execution.collect();
          expect(output.stdout()).toBe("output");
          expect(output.code).toBe(code);
        } else if (observation === "recv") {
          // Consume the terminal event through the event-reading path.
          while (await execution.recv() !== null) { /* drain */ }
        } else {
          expect((await execution.wait()).code).toBe(code);
        }
        expect((await execution.wait()).code).toBe(code);
        expect((await execution.wait()).code).toBe(code);
        expect(await execution.recv()).toBeNull();
        expect((await sb.shell(`wc -l < ${marker}`)).stdout().trim()).toBe("1");
      });
    }
  }

  it("reads configuration changes made through another receiver", async () => {
    const observer = await Sandbox.get(name);
    await sb.modify({ labels: { revision: "first" } });
    const captured = await observer.config();
    await sb.modify({ labels: { revision: "second" } });
    expect(captured.labels).toMatchObject({ revision: "first" });
    expect((await observer.config()).labels).toMatchObject({ revision: "second" });
  });

  it("retains volume builder destinations after their context variables leave scope", async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "sdk-contexts-")));
    // Returning only builders ensures the caller does not keep context variables alive.
    const builders = ["first", "second"].map((home) => {
      const context = LocalContext.builder().home(join(root, home)).build();
      return Volume.ctx(context).builder("same-name");
    });
    const volumes: Volume[] = [];
    try {
      for (const builder of builders) volumes.push(await builder.create());
      const [first, second] = volumes;
      // Resource IDs are scoped to their destination; two catalogs may both use local:1.
      expect(first.path).not.toBe(second.path);
      await first.fs().write("marker", "first");
      await second.fs().write("marker", "second");
      const fetched = await first.context.volumes.get("same-name");
      expect(await fetched.fs().readToString("marker")).toBe("first");
      await first.destroy();
      await expect(fetched.info()).rejects.toThrow();
      expect(await second.fs().readToString("marker")).toBe("second");
    } finally {
      for (const volume of volumes) await volume.destroy().catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects stale receivers after replacement instead of returning cached information", async () => {
    const stale = await Sandbox.builder(`${name}-replacement`).image("alpine").memory(256).create();
    await stale.config();
    await stale.stop();
    const replacement = await Sandbox.builder(stale.name).image("alpine").memory(256).replace().create();
    try {
      expect(replacement.id).not.toBe(stale.id);
      await expect(stale.config()).rejects.toThrow();
      await expect(stale.info()).rejects.toThrow();
      await expect(stale.destroy()).rejects.toThrow();
      expect((await replacement.shell("printf replacement")).stdout()).toBe("replacement");
    } finally {
      await replacement.destroy();
    }
  });

  it("retains implicit startup and respects borrowed disposal", async () => {
    await sb.stop();
    const receiver = await Sandbox.get(name);
    const identity = receiver.id;
    expect(typeof identity).toBe("string");
    expect(await receiver.status()).toBe("stopped");
    await receiver.config();
    expect(await receiver.status()).toBe("stopped");
    expect(receiver.ownsLifecycle).toBe(false);
    try {
      expect((await receiver.shell("printf prepared")).stdout()).toBe("prepared");
      expect(receiver.ownsLifecycle).toBe(true);
      expect(await receiver.ensureRunning()).toBeUndefined();
      const borrower = await Sandbox.getRunning(name);
      expect(borrower.ownsLifecycle).toBe(false);
      await borrower[Symbol.asyncDispose]();
      expect(await receiver.status()).toBe("running");
    } finally {
      await receiver[Symbol.asyncDispose]();
    }
    const observer = await Sandbox.get(name);
    expect(observer.id).toBe(identity);
    expect(await observer.waitForStatus("stopped")).toBeUndefined();
  });
});
