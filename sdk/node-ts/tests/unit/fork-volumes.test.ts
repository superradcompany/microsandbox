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
import { UnsupportedError } from "../../dist/errors.js";

const child = { id: "child-id", name: "child", backendKind: "local", ownsLifecycle: false };
const volumes = { "/data": (m: never) => (m as { disk(host: string): never }).disk("/images/seed.img") };

function source(kind: "sandbox" | "handle", extra: object) {
  const native = {
    id: "source-id", name: "source", backendKind: "local", ownsLifecycle: false,
    status: "running", configJson: "{}",
    fork: vi.fn(async () => child),
    forkMany: vi.fn(async () => [{ name: "a", sandbox: child }]),
    ...extra,
  };
  const wrapper = kind === "sandbox"
    ? new Sandbox(native as never, "source") : new SandboxHandle(native as never);
  return { native, wrapper };
}

describe("fork volumes", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    it(`${kind} fork and forkMany pass configured mounts to the native volume calls`, async () => {
      const { native, wrapper } = source(kind, {
        forkWithVolumes: vi.fn(async () => child),
        forkManyWithVolumes: vi.fn(async () => [{ name: "a", sandbox: child }]),
      });
      await wrapper.fork("c", { guestFlush: "skip", volumes });
      await wrapper.forkMany(["a"], { recordIntegrity: true, volumes });
      const [, , flush, mounts] = native.forkWithVolumes.mock.calls[0] as unknown as [string, boolean, string, object[]];
      expect(flush).toBe("skip");
      expect(mounts).toMatchObject([{ guest: "/data", host: "/images/seed.img" }]);
      expect(native.forkManyWithVolumes).toHaveBeenCalledOnce();
      expect(native.fork).not.toHaveBeenCalled();
      expect(native.forkMany).not.toHaveBeenCalled();
    });

    it(`${kind} refuses volumes when the native library predates them`, async () => {
      const { native, wrapper } = source(kind, {});
      await expect(wrapper.fork("c", { volumes })).rejects.toBeInstanceOf(UnsupportedError);
      await expect(wrapper.forkMany(["a"], { volumes })).rejects.toBeInstanceOf(UnsupportedError);
      await expect(wrapper.branch("c", { volumes })).rejects.toBeInstanceOf(UnsupportedError);
      expect(native.fork).not.toHaveBeenCalled();
      expect(native.forkMany).not.toHaveBeenCalled();
    });

    it(`${kind} fork without volumes keeps using the original native calls`, async () => {
      const { native, wrapper } = source(kind, {});
      await wrapper.fork("c");
      await wrapper.forkMany(["a"], { volumes: {} });
      expect(native.fork).toHaveBeenCalledOnce();
      expect(native.forkMany).toHaveBeenCalledOnce();
    });
  }
});
