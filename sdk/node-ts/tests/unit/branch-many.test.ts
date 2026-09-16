import { describe, expect, it, vi } from "vitest";

vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import { SandboxAlreadyExistsError } from "../../dist/errors.js";

describe("capture-once branch wrappers", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    it(`${kind} makes one native call and preserves ordered partial outcomes`, async () => {
      const child = { id: "child-id", name: "alice", backendKind: "local", ownsLifecycle: false };
      const native = {
        id: "source-id", name: "source", backendKind: "local", ownsLifecycle: false,
        status: "running", configJson: "{}",
        branch: vi.fn(),
        branchMany: vi.fn(async () => [
          { name: "alice", sandbox: child },
          { name: "bob", error: "[SandboxAlreadyExists] bob" },
        ]),
      };
      const source = kind === "sandbox"
        ? new Sandbox(native as never, "source") : new SandboxHandle(native as never);
      const results = await source.branchMany(["alice", "bob"], { recordIntegrity: true, guestFlush: "required" });
      expect(native.branchMany).toHaveBeenCalledExactlyOnceWith(["alice", "bob"], true, "required");
      expect(native.branch).not.toHaveBeenCalled();
      expect(results.map(r => r.name)).toEqual(["alice", "bob"]);
      expect(results[0]!.sandbox).toBeInstanceOf(Sandbox);
      expect(results[1]!.error).toBeInstanceOf(SandboxAlreadyExistsError);
    });
  }
});
