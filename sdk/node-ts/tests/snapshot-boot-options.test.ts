import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { Snapshot, Sandbox, type RestoreBuilder } from "../dist/index.js";

const archive = process.env.MSB_BOOT_ARCHIVE;
const full = process.env.MSB_BOOT_FULL === "1";
describe.skipIf(!archive)("snapshot destination boot options", () => {
  it("applies init argv/env and hostname only to new disk boots", async () => {
    const { snapshot: group } = await Snapshot.load(`boot-${randomUUID()}`, [archive!]);
    const checkpoint = (await group.head())!;
    const names: string[] = [];
    try {
      if (full) {
        for (const option of ["init", "hostname"] as const) {
          const name = `refuse-${randomUUID()}`;
          names.push(name);
          await expect(checkpoint.spawnSandboxWith(b => b.name(name)[option]("auto")))
            .rejects.toThrow(/disk-only/);
          await expect(Sandbox.get(name)).rejects.toThrow(/not found/i);
        }
      }
      for (const progress of [false, true]) {
        const name = `boot-${randomUUID()}`;
        names.push(name);
        const configure = (b: RestoreBuilder) => {
          b.workdir("/root").shell("/bin/ash").env("DEST_VALUE", "node-value")
            .entrypoint(["/bin/sh", "-c"]).cmd(['printf "%s:%s" "$PWD" "$DEST_VALUE"; touch /root/default-ran']);
          b.name(name).cpus(1).memory(256).maxCpus(2).maxMemory(512).labels({ destination: "node-child" }).hostname("node-child").initWith("/bin/sh", init =>
            init.args(["-c", 'printf "%s" "$BOOT_VALUE" > /root/node-boot; exec sleep 300'])
              .env("BOOT_VALUE", "node-init"));
          return full ? b.diskOnly() : b;
        };
        const child = progress
          ? await (await checkpoint.spawnSandboxWithProgressWith(configure)).awaitSandbox()
          : await group.spawnSandboxWith(configure);
        try {
          expect((await child.shell("test ! -e /root/default-ran")).success).toBe(true);
          const defaults = await child.execDefault();
          expect(defaults.success).toBe(true);
          expect(defaults.stdout()).toBe("/root:node-value");
          const config = (await Sandbox.get(name)).config();
          expect(config.resources.maxCpus).toBe(2);
          expect(config.resources.maxMemoryMib).toBe(512);
          expect(config.labels.destination).toBe("node-child");
          const capacity = await child.shell("nproc; cat /sys/devices/system/cpu/possible");
          expect(capacity.stdout().trim()).toBe("1\n0-1");
          const output = await child.shell('for i in $(seq 1 50); do test -s /root/node-boot && break; sleep 0.1; done; test "$(cat /root/node-boot)" = node-init && test "$(hostname)" = node-child && cat /proc/1/comm');
          expect(output.stdout().trim()).toBe("sleep");
        } finally {
          // sleep is deliberately not a production init and has no shutdown handler.
          await child.kill();
        }
      }
    } finally {
      for (const name of names) {
        try { await (await Sandbox.get(name)).kill(); } catch {}
        try { await Sandbox.remove(name); } catch {}
      }
      await group.remove();
    }
  }, 180_000);
});
