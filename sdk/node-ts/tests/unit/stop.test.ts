import { describe, expect, it, vi } from "vitest";

vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import { StopTimeoutError } from "../../dist/errors.js";

describe("graceful stop wrappers", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    function fixture() {
      const native = {
        id: "same-run", name: "fixture", backendKind: "local", ownsLifecycle: false,
        status: "running", configJson: "{}",
        stop: vi.fn(async () => {}), requestStop: vi.fn(async () => {}),
        stopWithTimeout: vi.fn(async (_ms: number) => {
          throw new Error("[StopTimeout] fixture did not complete; no kill was requested");
        }),
        kill: vi.fn(async () => {}),
      };
      const wrapper = kind === "sandbox"
        ? new Sandbox(native as never, "fixture") : new SandboxHandle(native as never);
      return { native, wrapper };
    }

    it(`${kind} dispatches indefinite Stop without a hidden budget`, async () => {
      const { native, wrapper } = fixture();
      await wrapper.stop();
      expect(native.stop).toHaveBeenCalledExactlyOnceWith();
      expect(native.stopWithTimeout).not.toHaveBeenCalled();
      expect(native.kill).not.toHaveBeenCalled();
    });

    it(`${kind} preserves typed zero and elapsed timeouts without force fallback`, async () => {
      const { native, wrapper } = fixture();
      for (const ms of [0, 30]) {
        await expect(wrapper.stopWithTimeout(ms)).rejects.toBeInstanceOf(StopTimeoutError);
        expect(native.stopWithTimeout).toHaveBeenLastCalledWith(ms);
      }
      expect(native.kill).not.toHaveBeenCalled();
    });

    it(`${kind} rejects lossy native timeout conversions before dispatch`, async () => {
      const { native, wrapper } = fixture();
      for (const ms of [-1, NaN, Infinity, 0.5, 4294967296]) {
        await expect(wrapper.stopWithTimeout(ms)).rejects.toBeInstanceOf(RangeError);
      }
      expect(native.stopWithTimeout).not.toHaveBeenCalled();
    });
  }
});
