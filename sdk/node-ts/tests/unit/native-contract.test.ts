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
