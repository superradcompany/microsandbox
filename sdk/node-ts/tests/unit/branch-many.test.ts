import { describe, expect, it, vi } from "vitest";

vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import { SandboxAlreadyExistsError } from "../../dist/errors.js";

describe("capture-once fork wrappers", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    for (const method of ["forkMany", "branchMany"] as const) {
      it(`${kind} ${method} makes one native call and preserves ordered partial outcomes`, async () => {
        const child = { id: "child-id", name: "alice", backendKind: "local", ownsLifecycle: false };
        const native = {
          id: "source-id", name: "source", backendKind: "local", ownsLifecycle: false,
          status: "running", configJson: "{}",
          fork: vi.fn(),
          forkMany: vi.fn(async () => [
            { name: "alice", sandbox: child },
            { name: "bob", error: "[SandboxAlreadyExists] bob" },
          ]),
        };
        const source = kind === "sandbox"
          ? new Sandbox(native as never, "source") : new SandboxHandle(native as never);
        const results = await source[method](["alice", "bob"], { recordIntegrity: true, guestFlush: "required" });
        expect(native.forkMany).toHaveBeenCalledExactlyOnceWith(["alice", "bob"], true, "required", undefined);
        expect(native.fork).not.toHaveBeenCalled();
        expect(results.map(r => r.name)).toEqual(["alice", "bob"]);
        expect(results[0]!.sandbox).toBeInstanceOf(Sandbox);
        expect(results[1]!.error).toBeInstanceOf(SandboxAlreadyExistsError);
      });
    }
  }
});
