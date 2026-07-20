import { describe, expect, it } from "vitest";
import { napi } from "../../dist/internal/napi.js";

describe("native Sandbox lifecycle contract", () => {
  it("exports the live lifecycle methods used by the TS wrapper", () => {
    const proto = napi.Sandbox.prototype as Record<string, unknown>;

    for (const method of [
      "stop",
      "requestStop",
      "stopWithTimeout",
      "kill",
      "requestKill",
      "killWithTimeout",
      "requestDrain",
      "waitUntilStopped",
      "ping",
      "touch",
      "modify",
    ]) {
      expect(typeof proto[method], method).toBe("function");
    }
  });

  it("exports the handle health methods used by the TS wrapper", () => {
    const proto = napi.SandboxHandle.prototype as Record<string, unknown>;

    for (const method of ["ping", "touch", "modify"]) {
      expect(typeof proto[method], method).toBe("function");
    }
  });
});

describe("native ExecHandle contract", () => {
  it("exports the TTY resize method used by the TS wrapper", () => {
    const proto = napi.ExecHandle.prototype as Record<string, unknown>;
    expect(typeof proto.resize).toBe("function");
  });
});

describe("native image cache contract", () => {
  it("exports the image functions used by the TS wrapper", () => {
    const fns = napi as unknown as Record<string, unknown>;

    for (const fn of [
      "imageGet",
      "imageList",
      "imageInspect",
      "imageRemove",
      "imagePrune",
      "imageLoad",
      "imageSave",
    ]) {
      expect(typeof fns[fn], fn).toBe("function");
    }
  });
});
