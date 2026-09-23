import { describe, expect, it, vi } from "vitest";

vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";

describe("guest writeback forwarding", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    it(`${kind} forwards explicit policy and preserves ordinary pause`, async () => {
      const native = {
        id: "source-id", name: "source", backendKind: "local", ownsLifecycle: false,
        status: "running", configJson: "{}", pause: vi.fn(async () => {}),
        branch: vi.fn(async () => ({ id: "child-id", name: "child", backendKind: "local", ownsLifecycle: false })),
      };
      const source = kind === "sandbox"
        ? new Sandbox(native as never, "source") : new SandboxHandle(native as never);
      await source.pause();
      expect(native.pause).toHaveBeenLastCalledWith(undefined);
      await source.pause({ guestFlush: "required" });
      expect(native.pause).toHaveBeenLastCalledWith("required");
      await source.branch("child", { guestFlush: "skip" });
      expect(native.branch).toHaveBeenLastCalledWith("child", undefined, "skip");
    });
  }
});
