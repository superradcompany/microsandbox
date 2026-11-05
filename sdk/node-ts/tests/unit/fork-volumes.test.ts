import { describe, expect, it, vi } from "vitest";

vi.mock("../../dist/internal/napi.js", () => ({
  napi: {
    MountBuilder: class {
      constructor(readonly guest: string) {}
      disk(host: string) { return Object.assign(this, { host }); }
    },
  },
}));
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";

const child = { id: "child-id", name: "child", backendKind: "local", ownsLifecycle: false };
const volumes = { "/data": (m: never) => (m as { disk(host: string): never }).disk("/images/seed.img") };

function source(kind: "sandbox" | "handle") {
  const native = {
    id: "source-id", name: "source", backendKind: "local", ownsLifecycle: false,
    status: "running", configJson: "{}",
    fork: vi.fn(async () => child),
    forkMany: vi.fn(async () => [{ name: "a", sandbox: child }]),
  };
  const wrapper = kind === "sandbox"
    ? new Sandbox(native as never, "source") : new SandboxHandle(native as never);
  return { native, wrapper };
}

describe("fork volumes", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    it(`${kind} fork and forkMany pass configured mounts to the existing native calls`, async () => {
      const { native, wrapper } = source(kind);
      await wrapper.fork("c", { guestFlush: "skip", volumes });
      await wrapper.forkMany(["a"], { recordIntegrity: true, volumes });
      const [, , flush, mounts] = native.fork.mock.calls[0] as unknown as [string, boolean, string, object[]];
      expect(flush).toBe("skip");
      expect(mounts).toMatchObject([{ guest: "/data", host: "/images/seed.img" }]);
      expect(native.forkMany).toHaveBeenCalledOnce();
      expect(native.forkMany.mock.calls[0]).toMatchObject([["a"], true, undefined, [{ guest: "/data", host: "/images/seed.img" }]]);
      expect(native.fork).toHaveBeenCalledOnce();
    });

    it(`${kind} fork without volumes keeps using the original native calls`, async () => {
      const { native, wrapper } = source(kind);
      await wrapper.fork("c");
      await wrapper.forkMany(["a"], { volumes: {} });
      expect(native.fork).toHaveBeenCalledOnce();
      expect(native.forkMany).toHaveBeenCalledOnce();
    });
  }
});
