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

    it(`${kind} preserves the stop timeout validation message`, async () => {
      const { native, wrapper } = fixture();

      await expect(wrapper.stopWithTimeout(-1)).rejects.toThrow(
        "stop timeout must be an integer from 0 to 4294967295 milliseconds",
      );

      expect(native.stopWithTimeout).not.toHaveBeenCalled();
    });

    it(`${kind} forwards the maximum stop timeout unchanged`, async () => {
      const { native, wrapper } = fixture();

      await expect(wrapper.stopWithTimeout(4294967295)).rejects.toBeInstanceOf(StopTimeoutError);

      expect(native.stopWithTimeout).toHaveBeenCalledExactlyOnceWith(4294967295);
      expect(native.kill).not.toHaveBeenCalled();
    });
  }
});

describe("kill timeout wrappers", () => {
  for (const kind of ["sandbox", "handle"] as const) {
    function fixture() {
      const native = {
        id: "same-run", name: "fixture", backendKind: "local", ownsLifecycle: false,
        status: "running", configJson: "{}",
        killWithTimeout: vi.fn(async (_ms: number) => {}),
      };
      const wrapper = kind === "sandbox"
        ? new Sandbox(native as never, "fixture") : new SandboxHandle(native as never);
      return { native, wrapper };
    }

    it.each([-1, NaN, Infinity, 0.5, 4294967296])(`${kind} rejects %s before dispatch`, async (ms) => {
      const { native, wrapper } = fixture();

      const result = wrapper.killWithTimeout(ms);
      await expect(result).rejects.toBeInstanceOf(RangeError);
      await expect(result).rejects.toThrow(
        "kill timeout must be an integer from 0 to 4294967295 milliseconds",
      );

      expect(native.killWithTimeout).not.toHaveBeenCalled();
    });

    it.each([0, 4294967295])(`${kind} forwards %s unchanged`, async (ms) => {
      const { native, wrapper } = fixture();

      await wrapper.killWithTimeout(ms);

      expect(native.killWithTimeout).toHaveBeenCalledExactlyOnceWith(ms);
    });
  }
});

describe("connect timeout wrapper", () => {
  function fixture() {
    const connected = {
      id: "same-run", name: "fixture", backendKind: "local", ownsLifecycle: false,
    };
    const native = {
      ...connected, status: "running", configJson: "{}",
      connectWithTimeout: vi.fn(async (_ms: number) => connected),
    };
    return { native, wrapper: new SandboxHandle(native as never) };
  }

  it.each([-1, NaN, Infinity, 0.5, 4294967296])("handle rejects %s before dispatch", async (ms) => {
    const { native, wrapper } = fixture();

    const result = wrapper.connectWithTimeout(ms);
    await expect(result).rejects.toBeInstanceOf(RangeError);
    await expect(result).rejects.toThrow(
      "connect timeout must be an integer from 0 to 4294967295 milliseconds",
    );

    expect(native.connectWithTimeout).not.toHaveBeenCalled();
  });

  it.each([0, 4294967295])("handle forwards %s unchanged", async (ms) => {
    const { native, wrapper } = fixture();

    const connected = await wrapper.connectWithTimeout(ms);

    expect(native.connectWithTimeout).toHaveBeenCalledExactlyOnceWith(ms);
    expect(connected).toBeInstanceOf(Sandbox);
    expect(connected.id).toBe(native.id);
    expect(connected.ownsLifecycle).toBe(false);
  });
});
