import { beforeEach, describe, expect, it, vi } from "vitest";
const { binding } = vi.hoisted(() => ({ binding: {} as { snapshotArchiveCompatibilityTargets?: () => string[] } }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: binding }));
vi.mock("../../dist/sandbox.js", () => ({ Sandbox: class {} }));
import { Snapshot, SnapshotSaveOptions } from "../../dist/snapshot.js";
import { UnsupportedError } from "../../dist/errors.js";

describe("archive recipient capability", () => {
  beforeEach(() => { delete binding.snapshotArchiveCompatibilityTargets; });
  it("keeps existing saves available on older native libraries", async () => {
    const saveTo = vi.fn().mockResolvedValue(undefined);
    await new Snapshot({ saveTo } as never).save("out.msb");
    expect(saveTo).toHaveBeenCalledWith("out.msb", undefined);
  });
  it.each(["current", "0.7.8"] as const)("refuses ignored explicit target %s before invoking old native code", async compatibility => {
    const saveTo = vi.fn();
    await expect(new Snapshot({ saveTo } as never).saveTo("out.msb", { compatibility })).rejects.toBeInstanceOf(UnsupportedError);
    expect(saveTo).not.toHaveBeenCalled();
  });
  it("passes a recognized explicit target through the fluent API", async () => {
    binding.snapshotArchiveCompatibilityTargets = () => ["current", "0.7.8"];
    const saveTo = vi.fn().mockResolvedValue(undefined);
    await new Snapshot({ saveTo } as never).saveWith("out.msb", options => options.compatibility("0.7.8").withImage());
    expect(saveTo).toHaveBeenCalledWith("out.msb", { compatibility: "0.7.8", withImage: true });
    expect(new SnapshotSaveOptions().toNative()).toEqual({});
  });
});
