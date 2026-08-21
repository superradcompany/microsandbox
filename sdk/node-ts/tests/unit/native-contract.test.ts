import { afterEach, describe, expect, it, vi } from "vitest";
import { napi } from "../../dist/internal/napi.js";
import { Sandbox } from "../../dist/sandbox.js";

afterEach(() => {
  vi.restoreAllMocks();
});

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
      "waitForStatus",
      "restart",
      "destroy",
      "waitUntilStopped",
      "ping",
      "touch",
      "modify",
      "execDefault",
      "execDefaultWithBuilder",
      "execDefaultStream",
      "execDefaultStreamWithBuilder",
      "attachDefault",
      "attachDefaultWithBuilder",
    ]) {
      expect(typeof proto[method], method).toBe("function");
    }
  });

  it("exports the durable CMD setter and convergent terminal", () => {
    const proto = napi.SandboxBuilder.prototype as Record<string, unknown>;
    expect(typeof proto.cmd).toBe("function");
    expect(typeof proto.connectOrCreate).toBe("function");
    expect(typeof proto.fromSnapshotRef).toBe("function");
  });

  it("dispatches strings and typed snapshot references to the matching native setter", () => {
    const fromSnapshot = vi
      .spyOn(napi.SandboxBuilder.prototype, "fromSnapshot")
      .mockImplementation(function () {
        return this;
      });
    const fromSnapshotRef = vi
      .spyOn(napi.SandboxBuilder.prototype, "fromSnapshotRef")
      .mockImplementation(function () {
        return this;
      });

    Sandbox.builder("from-string").fromSnapshot("nightly");
    expect(fromSnapshot).toHaveBeenCalledWith("nightly");
    expect(fromSnapshotRef).not.toHaveBeenCalled();

    Sandbox.builder("from-object").fromSnapshot({
      reference: "snapshot-id",
      referenceKind: "id",
    });
    expect(fromSnapshotRef).toHaveBeenCalledWith("snapshot-id", "id");
  });

  it("exports the handle health methods used by the TS wrapper", () => {
    const proto = napi.SandboxHandle.prototype as Record<string, unknown>;

    for (const method of [
      "ping",
      "touch",
      "modify",
      "connectOrStart",
      "waitForStatus",
      "restart",
      "destroy",
    ]) {
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

describe("native snapshot contract", () => {
  it("exports instance archive methods", () => {
    expect(typeof napi.Snapshot.prototype.saveTo).toBe("function");
    expect(typeof napi.SnapshotHandle.prototype.saveTo).toBe("function");
  });
});
