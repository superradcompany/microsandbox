import { afterEach, describe, expect, it, vi } from "vitest";
import { napi } from "../../dist/internal/napi.js";
import { Sandbox } from "../../dist/sandbox.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("native Sandbox lifecycle contract", () => {
  it("exports getRunning as a native static factory", () => {
    expect(typeof napi.Sandbox.getRunning).toBe("function");
  });

  it("exports the live lifecycle methods used by the TS wrapper", () => {
    const proto = napi.Sandbox.prototype as Record<string, unknown>;

    for (const method of [
      "ensureRunning",
      "infoJson",
      "configJson",
      "stop",
      "shutdownOwned",
      "detach",
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
      "modifyWithResizeTracking",
      "resizeOperations",
      "waitForResizeOperations",
      "resizeStatus",
      "waitUntilResized",
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
    expect(proto.fromSnapshot).toBeUndefined();
    expect(proto.fromSnapshotRef).toBeUndefined();
  });

  it("accepts strings and typed snapshot references through dedicated restore", () => {
    expect(() => Sandbox.restore("nightly").name("from-string")).not.toThrow();
    expect(() => Sandbox.restore({ reference: "snapshot-id", referenceKind: "id" }).name("from-id")).not.toThrow();
    expect(() => Sandbox.restore({ reference: "snapshot-path", referenceKind: "path" }).name("from-path")).not.toThrow();
    expect(() => new napi.RestoreBuilder("snapshot", "invalid" as never)).toThrow("unknown snapshot reference kind");
  });

  it("exposes narrow destination controls on the dedicated restore builder", () => {
    const builder = new napi.RestoreBuilder("snapshot").name("destination");
    expect(builder.cpus(2).memory(512).maxTcpConnections(0).maxUdpConnections(7).disableNetwork()
      .security("default").maxDurationSeconds(0).idleTimeoutSeconds(0)).toBe(builder);
    expect(builder.maxConnections(64).maxUdpConnections(0)).toBe(builder);
    expect(builder.port(8080, 80).tcpAcceptQueueSize(4096)).toBe(builder);
    expect(() => builder.networkPolicyJson(JSON.stringify({
      default_egress: "deny", default_ingress: "deny", rules: [],
    }))).not.toThrow();
    expect(() => builder.networkPolicyJson(JSON.stringify({ tls: {} })))
      .toThrow("restore network policy accepts only default actions and rules");
    expect(() => builder.cpus(256)).toThrow("cpus out of u8 range");
    expect(() => builder.maxCpus(256)).toThrow("max_cpus out of u8 range");
    for (const value of [-1, 1.5, NaN, Infinity, -Infinity, 2 ** 32]) {
      expect(() => builder.maxCpus(value)).toThrow();
      expect(() => builder.maxMemory(value)).toThrow();
    }
    // Numeric refusal must leave the deferred builder reusable. Zero remains
    // explicit here; core resource validation rejects it at the terminal call.
    expect(builder.maxCpus(0).maxMemory(0).maxCpus(2).maxMemory(512)).toBe(builder);
    expect(builder.label("team", "first").labels({ team: "last" })).toBe(builder);
    expect(builder.workdir("/root").shell("/bin/ash").entrypoint([]).cmd([])
      .env("EMPTY", "").envs({ DEST: "value" })).toBe(builder);
    expect(() => builder.security("invalid" as never)).toThrow("invalid security profile");
    for (const value of [-1, NaN, Infinity, -Infinity, 0.5, 1.5, Number.MIN_VALUE, 2 ** 53]) {
      expect(() => builder.maxDurationSeconds(value)).toThrow("must be a non-negative safe integer");
      expect(() => builder.idleTimeoutSeconds(value)).toThrow("must be a non-negative safe integer");
    }
    // Rejected values must not consume the builder or change valid limit semantics.
    for (const value of [0, -0, 1, Number.MAX_SAFE_INTEGER]) {
      expect(builder.maxDurationSeconds(value).idleTimeoutSeconds(value)).toBe(builder);
    }
    for (const method of ["image", "network", "foregroundCommand", "backgroundCommand", "replace", "create"]) {
      expect((builder as unknown as Record<string, unknown>)[method], method).toBeUndefined();
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
  it("exports group creation, import, and head selection", () => {
    expect(typeof napi.Snapshot.loadWithOptions).toBe("function");
    expect(typeof napi.Snapshot.loadMany).toBe("function");
    expect(typeof napi.Snapshot.readGroupHead).toBe("function");
    expect(typeof napi.Snapshot.setGroupHead).toBe("function");
    expect(typeof napi.SnapshotBuilder.prototype.group).toBe("function");
    const builder = new napi.SnapshotBuilder("").fromSandbox("source").group("work");
    const config = (builder as unknown as { build(): { name: string; group: string } }).build();
    expect(config.name).toBe("");
    expect(config.group).toBe("work");
  });
  it("exports the direct archive result used by the TS wrapper", () => {
    expect(typeof napi.SnapshotArchive).toBe("function");
  });
  it("passes empty batches to core validation", async () => {
    await expect(napi.Snapshot.loadMany([])).rejects.toThrow(
      "snapshot load requires at least one archive",
    );
  });
  it("exports instance archive methods", () => {
    expect(typeof napi.Snapshot.prototype.saveTo).toBe("function");
    expect(typeof napi.Snapshot.prototype.copyTo).toBe("function");
    expect(typeof napi.Snapshot.prototype.saveTo).toBe("function");
  });
});


describe("native storage contract", () => {
  it("exports storage observation and runtime RAM pruning", () => {
    expect(typeof napi.storageUsage).toBe("function");
    expect(typeof napi.storagePrune).toBe("function");
  });
});

it("refuses a conflicting legacy group before reading archives", async () => {
  await expect(napi.SnapshotGroup.load("selected", ["missing.msb"], { group: "other" }))
    .rejects.toThrow("different destination group");
});
