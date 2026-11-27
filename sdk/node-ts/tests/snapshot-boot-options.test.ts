import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { Snapshot, Sandbox, NetworkPolicy, type RestoreBuilder } from "../dist/index.js";

const archive = process.env.MSB_BOOT_ARCHIVE;
const full = process.env.MSB_BOOT_FULL === "1";
describe.skipIf(!archive)("snapshot destination boot options", () => {
  it("grows only the child root and binds a secret before its first boot", async () => {
    const { snapshot: group } = await Snapshot.load(`capacity-${randomUUID()}`, [archive!]);
    const checkpoint = (await group.head())!;
    const names: string[] = [];
    const value = randomUUID();
    const server = createServer((request, response) => {
      const accepted = request.headers.authorization === `Bearer ${value}`;
      response.writeHead(accepted ? 200 : 401);
      response.end(accepted ? "destination-credential-accepted\n" : "unauthorized\n");
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = (server.address() as { port: number }).port;
    const scope = (builder: RestoreBuilder) => full ? builder.diskOnly() : builder;
    const capacity = async (sandbox: Sandbox) => {
      const output = await sandbox.shell("df -Pk / | awk 'NR==2 {print $2}'");
      expect(output.success).toBe(true);
      return Number(output.stdout().trim());
    };
    const remove = async (name: string) => {
      try { await (await Sandbox.get(name)).destroy({ force: true }); }
      catch (error) { if (!String(error).includes("not found")) throw error; }
    };
    try {
      const baselineName = `capacity-base-${randomUUID()}`;
      names.push(baselineName);
      const baseline = await checkpoint.spawnSandboxWith(builder => scope(builder.name(baselineName)));
      const originalKiB = await capacity(baseline);
      expect(originalKiB).toBeGreaterThan(0);
      await remove(baselineName);
      const requestedMiB = Math.ceil(originalKiB / 1024) + 1024;

      if (full) {
        const refused = `capacity-refused-${randomUUID()}`;
        names.push(refused);
        await expect(checkpoint.spawnSandboxWith(builder => builder.name(refused).rootDisk(requestedMiB)))
          .rejects.toThrow(/disk-only/);
        await expect(Sandbox.get(refused)).rejects.toThrow(/not found/i);
      }

      const name = `capacity-child-${randomUUID()}`;
      names.push(name);
      const child = await scope(Sandbox.restore(checkpoint).name(name))
        .rootDisk(requestedMiB)
        .networkPolicy(NetworkPolicy.allowAll())
        .secret(secret => secret.env("RESTORE_KEY").value(value).placeholder("restore-placeholder")
          .allow("host.microsandbox.internal").requireTlsIdentity(false))
        .secretViolationAction("block-and-log")
        .initWith("/bin/sh", init => init.args(["-c", "echo boot >> /root/destination-boots; exec sleep 300"]))
        .restore();
      expect(await capacity(child)).toBeGreaterThan(originalKiB + 400 * 1024);
      const firstCommand = await child.shell(`for i in $(seq 1 50); do test -s /root/destination-boots && break; sleep 0.1; done
test "$(wc -l < /root/destination-boots)" -eq 1 && test -s /.msb/tls/ca.pem && test "$RESTORE_KEY" = restore-placeholder &&
wget -T 5 -qO- --header 'Authorization: Bearer restore-placeholder' http://host.microsandbox.internal:${port}/probe`);
      expect(firstCommand.success).toBe(true);
      expect(firstCommand.stdout()).toBe("destination-credential-accepted\n");
      await remove(name);

      const siblingName = `capacity-sibling-${randomUUID()}`;
      names.push(siblingName);
      const sibling = await checkpoint.spawnSandboxWith(builder => scope(builder.name(siblingName)));
      expect(await capacity(sibling)).toBe(originalKiB);
      expect((await sibling.shell("test ! -e /root/destination-boots")).success).toBe(true);
    } finally {
      for (const name of names) await remove(name);
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      await group.remove();
    }
  }, 180_000);

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
          const config = await (await Sandbox.get(name)).config();
          expect(config.spec.resources.maxCpus).toBe(2);
          expect(config.spec.resources.maxMemoryMib).toBe(512);
          expect(config.spec.labels.destination).toBe("node-child");
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
