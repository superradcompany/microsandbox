import { describe, expect, it, vi } from "vitest";
const { native } = vi.hoisted(() => ({ native: { name: vi.fn(), restore: vi.fn(), restoreWithProgress: vi.fn() } as Record<string, any> }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: { RestoreBuilder: class { constructor() { return native; } } } }));
import { Sandbox } from "../../dist/sandbox.js";
import { UnsupportedError } from "../../dist/errors.js";

describe("restore guest clock capability", () => {
  it("refuses an explicit clock on an older addon without preventing ordinary restore", () => {
    delete native.guestClock;
    const builder = Sandbox.restore("saved");
    expect(typeof builder.restore).toBe("function");
    expect(() => builder.guestClock("off")).toThrow(UnsupportedError);
    expect(() => builder.guestClock("sync")).toThrow(/updated native SDK/);
  });
  it("retains the recognized native setter", () => {
    const setter = vi.fn().mockReturnValue(native);
    native.guestClock = setter;
    Sandbox.restore("saved").guestClock("off");
    expect(setter).toHaveBeenCalledWith("off");
  });
});
