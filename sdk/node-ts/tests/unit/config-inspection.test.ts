import { describe, expect, it } from "vitest";
import { Sandbox } from "../../dist/sandbox.js";

function inspect(kind: "local" | "remote", spec: object) {
  const native = { configJson: async () => JSON.stringify({ kind, spec }) };
  return new Sandbox(native as never, "fixture").config();
}

describe("configuration inspection", () => {
  it.each([["Always", "always"], ["IfMissing", "if-missing"], ["Never", "never"]])(
    "reads the public spelling of persisted policy %s",
    async (wire, policy) => {
      const view = await inspect("local", { pull_policy: wire, runtime: { log_level: "warn" } });
      expect(view.spec).toEqual({ pullPolicy: policy, runtime: { logLevel: "warn" } });
    },
  );

  it("preserves an unset remote level and omitted policy", async () => {
    const view = await inspect("remote", { runtime: { log_level: null } });
    expect(view.spec).toEqual({ runtime: { logLevel: null } });
  });
});
