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
    ]) {
      expect(typeof proto[method], method).toBe("function");
    }
  });
});
