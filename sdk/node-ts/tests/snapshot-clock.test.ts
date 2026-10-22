import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { Snapshot, Sandbox, type RestoreBuilder } from "../dist/index.js";

const archive = process.env.MSB_CLOCK_ARCHIVE;
describe.skipIf(!archive)("snapshot clock inheritance", () => {
  it("preserves the recorded/default policy and applies explicit direct/progress overrides", async () => {
    const imported = await Snapshot.load(`node-clock-${randomUUID()}`, [archive!]);
    const group = imported.snapshot;
    const checkpoint = await group.head();
    expect(checkpoint).not.toBeNull();
    const names: string[] = [];
    try {
      for (const [source, policy, progress] of [
        [group, undefined, false], [checkpoint!, "sync", false],
        [group, "off", true], [checkpoint!, undefined, true],
      ] as const) {
        const name = `node-clock-${randomUUID()}`;
        names.push(name);
        const configure = (builder: RestoreBuilder) => policy ? builder.name(name).guestClock(policy) : builder.name(name);
        const child = progress
          ? await (await source.spawnSandboxWithProgressWith(configure)).awaitSandbox()
          : await source.spawnSandboxWith(configure);
        const config = JSON.parse((await Sandbox.get(name)).configJson);
        expect(config.runtime.guest_clock ?? "sync").toBe(policy ?? process.env.MSB_CLOCK_EXPECTED ?? "sync");
        expect((await child.shell("cat /root/clock-marker")).stdout()).toBe("clock-marker");
        await child.stop();
      }
    } finally {
      for (const name of names) {
        try { await (await Sandbox.get(name)).stop(); } catch {}
        try { await Sandbox.remove(name); } catch {}
      }
      await group.remove();
    }
  }, 180_000);
});
