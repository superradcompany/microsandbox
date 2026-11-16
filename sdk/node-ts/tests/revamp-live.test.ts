import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Sandbox } from "../dist/index.js";
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
