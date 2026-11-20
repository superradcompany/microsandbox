import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { Snapshot, Sandbox, SecretSource, NetworkPolicy, type RestoreBuilder } from "../dist/index.js";

const archive = process.env.MSB_PROXY_ARCHIVE;
const address = process.env.MSB_PROXY_ADDRESS;

// The parent harness owns a local SOCKS server that serves fixed bytes, never an external target.
describe.skipIf(!archive || !address)("snapshot destination proxy", () => {
  it("authenticates through group and exact-member progress spawning", async () => {
    const { snapshot: group } = await Snapshot.load(`proxy-${randomUUID()}`, [archive!]);
    const checkpoint = (await group.head())!;
    try {
      for (const progress of [false, true]) {
        const name = `proxy-${randomUUID()}`;
        let child: Sandbox | undefined;
        try {
          const configure = (b: RestoreBuilder) => b.name(name).port(0, 18080)
            .networkPolicy(NetworkPolicy.allowAll())
            .proxy(p => p.socks5(address!).credentials("fixture", SecretSource.env("MSB_SDK_PROXY_FIXTURE_PASSWORD")));
          child = progress
            ? await (await checkpoint.spawnSandboxWithProgressWith(configure)).awaitSandbox()
            : await group.spawnSandboxWith(configure);
          const response = await child.shell("wget -T 3 -qO- http://198.51.100.10:19090/probe");
          expect(response.success).toBe(true);
          expect(response.stdout()).toBe("snapshot-destination-proxy\n");
          expect((await child.shell("printf still-running")).stdout()).toBe("still-running");
        } finally {
          if (child) await child.stop();
          // Preserve the original failure if no catalog row was ever published.
          try { await Sandbox.remove(name); } catch (error) {
            if (!String(error).includes("not found")) throw error;
          }
        }
      }
    } finally {
      await group.remove();
    }
  }, 120_000);
});
