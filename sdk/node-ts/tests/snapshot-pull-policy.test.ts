import { describe, expect, it } from "vitest";
import { Snapshot, Sandbox, type PullPolicy, type RestoreBuilder } from "../dist/index.js";

const archive = process.env.MSB_PULL_ARCHIVE;
describe.skipIf(!archive)("snapshot pull policy", () => {
  it("spawns cached and registry-validated disk/full children", async () => {
    const { snapshot: group } = await Snapshot.load("node-pull-history", [archive!]);
    const checkpoint = (await group.head())!;
    try {
      for (const policy of ["never", "if-missing", "always"] as PullPolicy[]) {
        const name = `node-pull-${policy}`;
        let child: Sandbox | undefined;
        try {
          const configure = (b: RestoreBuilder) => b.name(name).port(0, 18080).pullPolicy(policy);
          child = policy === "never" ? await group.spawnSandboxWith(configure)
            : await (await checkpoint.spawnSandboxWithProgressWith(configure)).awaitSandbox();
          const result = await child.shell("printf policy-alive");
          expect(result.success).toBe(true);
          expect(result.stdout()).toBe("policy-alive");
        } finally {
          if (child) { await child.stop(); await Sandbox.remove(name); }
        }
      }
    } finally { await group.remove(); }
  }, 180_000);
});
