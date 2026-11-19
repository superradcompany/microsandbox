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


describe("restore boot option capabilities", () => {
  for (const option of ["init", "initWith", "hostname"] as const) {
    it(`refuses unsupported ${option} without invoking native restore`, () => {
      delete native[option];
      const builder = Sandbox.restore("saved");
      expect(() => builder[option]("auto", (init: any) => init)).toThrow(UnsupportedError);
      expect(typeof builder.restore).toBe("function");
    });
    it(`retains the native ${option} setter`, () => {
      const setter = vi.fn().mockReturnValue(native);
      native[option] = setter;
      const configure = (init: any) => init;
      Sandbox.restore("saved")[option]("chosen", configure);
      expect(setter).toHaveBeenCalledWith("chosen", configure);
    });
  }
});


describe("restore resource ceiling capabilities", () => {
  for (const option of ["maxCpus", "maxMemory"] as const) {
    it(`rejects unsupported ${option} before a terminal call`, () => {
      delete native[option];
      // Sandbox.restore wraps terminal methods; retain the original native spies.
      const restore = vi.fn();
      const progress = vi.fn();
      native.restore = restore;
      native.restoreWithProgress = progress;
      const builder = Sandbox.restore("saved");
      expect(() => builder[option](0)).toThrow(UnsupportedError);
      expect(restore).not.toHaveBeenCalled();
      expect(progress).not.toHaveBeenCalled();
    });
    it(`preserves explicit zero and the native ${option} setter`, () => {
      const setter = vi.fn().mockReturnValue(native);
      native[option] = setter;
      Sandbox.restore("saved")[option](0);
      expect(setter).toHaveBeenCalledWith(0);
    });
  }
});


describe("restore destination policy capabilities", () => {
  for (const option of ["label", "labels", "workdir", "shell", "entrypoint", "cmd", "env", "envs", "proxy", "pullPolicy"] as const) {
    it(`refuses missing ${option} before dispatch and preserves recognized setters`, () => {
      delete native[option];
      const restore = vi.fn();
      native.restore = restore;
      const builder = Sandbox.restore("saved");
      expect(() => (builder[option] as Function)("value")).toThrow(UnsupportedError);
      expect(restore).not.toHaveBeenCalled();
      const setter = vi.fn().mockReturnValue(native);
      native[option] = setter;
      (Sandbox.restore("saved")[option] as Function)("value");
      expect(setter).toHaveBeenCalledWith("value");
    });
  }
});
