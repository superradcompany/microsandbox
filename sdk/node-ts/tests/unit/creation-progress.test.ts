import { beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({
  ownsLifecycle: false,
  requestedDetached: undefined as boolean | undefined,
  stop: vi.fn(async () => {}),
  cancel: vi.fn(),
  create: vi.fn(),
  restoreSeed: vi.fn(),
  restore: vi.fn(),
  controls: vi.fn(),
}));

vi.mock("../../dist/internal/napi.js", () => {
  const sandbox = () => ({
    id: "restored-id",
    backendKind: "local",
    ownsLifecycle: native.ownsLifecycle,
    stop: native.stop,
  });
  const progress = () => ({
    cancel: native.cancel,
    progress: {},
    awaitSandbox: async () => sandbox(),
  });
  return {
    napi: {
      SandboxBuilder: class {
        detached(enabled: boolean): this {
          native.requestedDetached = enabled;
          return this;
        }
        async create() {
          native.create();
          return sandbox();
        }
        async connectOrCreate() { throw new Error("not used by progress tests"); }
        async createWithPullProgress() { return progress(); }
        async createWithProgress() { return progress(); }
      },
      RestoreBuilder: class {
        constructor(reference: string, referenceKind?: string) {
          native.restoreSeed(reference, referenceKind);
        }
        name(_name: string): this { return this; }
        cpus(value: number): this { native.controls("cpus", value); return this; }
        memory(value: number): this { native.controls("memory", value); return this; }
        networkPolicy(value: unknown): this { native.controls("networkPolicy", value); return this; }
        maxConnections(value: number): this { native.controls("maxConnections", value); return this; }
        maxTcpConnections(value: number): this { native.controls("maxTcpConnections", value); return this; }
        maxUdpConnections(value: number): this { native.controls("maxUdpConnections", value); return this; }
        disableNetwork(): this { native.controls("disableNetwork"); return this; }
        security(value: string): this { native.controls("security", value); return this; }
        maxDuration(value: number): this { native.controls("maxDuration", value); return this; }
        idleTimeout(value: number): this { native.controls("idleTimeout", value); return this; }
        async restore() {
          native.restore();
          return sandbox();
        }
        async restoreWithProgress() { return progress(); }
      },
    },
  };
});

import { Sandbox } from "../../dist/sandbox.js";

describe("creation result lifecycle ownership", () => {
  beforeEach(() => {
    native.ownsLifecycle = false;
    native.requestedDetached = undefined;
    native.stop.mockClear();
    native.cancel.mockClear();
    native.create.mockClear();
    native.restoreSeed.mockClear();
    native.restore.mockClear();
    native.controls.mockClear();
  });

  for (const method of ["create", "createWithProgress", "createWithPullProgress"] as const) {
    for (const ownsLifecycle of [false, true]) {
      it(`${method} disposes only when the returned native handle owns its lifecycle (${ownsLifecycle})`, async () => {
        native.ownsLifecycle = ownsLifecycle;
        // Lifecycle ownership is authoritative on the returned handle, not its builder.
        const builder = Sandbox.builder("restored").detached(false);
        const sandbox = method === "create"
          ? await builder.create()
          : await (await builder[method]()).awaitSandbox();

        expect(native.requestedDetached).toBe(false);
        expect(native.create).toHaveBeenCalledTimes(method === "create" ? 1 : 0);
        expect(sandbox.ownsLifecycle).toBe(ownsLifecycle);
        expect(sandbox.id).toBe("restored-id");
        await sandbox[Symbol.asyncDispose]();
        expect(native.stop).toHaveBeenCalledTimes(ownsLifecycle ? 1 : 0);
      });
    }
  }

  for (const method of ["restore", "restoreWithProgress"] as const) {
    it(`${method} retains explicit destination controls and zero limits`, async () => {
      const policy = { defaultEgress: "deny" as const, defaultIngress: "deny" as const, rules: [] };
      const builder = Sandbox.restore("baseline").name("destination")
        .cpus(2).memory(512).networkPolicy(policy).maxTcpConnections(0).maxUdpConnections(7)
        .disableNetwork().security("default").maxDuration(0).idleTimeout(0);
      if (method === "restore") await builder.restore();
      else await (await builder.restoreWithProgress()).awaitSandbox();
      expect(native.controls.mock.calls).toEqual([
        ["cpus", 2], ["memory", 512], ["networkPolicy", policy],
        ["maxTcpConnections", 0], ["maxUdpConnections", 7],
        ["disableNetwork"], ["security", "default"], ["maxDuration", 0], ["idleTimeout", 0],
      ]);
      expect(native.create).not.toHaveBeenCalled();
    });
    for (const tcpMethod of ["maxTcpConnections", "maxConnections"] as const) {
      it(`${method} forwards ${tcpMethod} independently of an explicit unlimited UDP limit`, async () => {
        const builder = Sandbox.restore("baseline").name("destination")
          [tcpMethod](64).maxUdpConnections(0);
        if (method === "restore") await builder.restore();
        else await (await builder.restoreWithProgress()).awaitSandbox();
        expect(native.controls.mock.calls).toEqual([[tcpMethod, 64], ["maxUdpConnections", 0]]);
        expect(native.create).not.toHaveBeenCalled();
      });
    }
    it(`${method} leaves omitted destination limits untouched`, async () => {
      const builder = Sandbox.restore("baseline").name("destination");
      if (method === "restore") await builder.restore();
      else await (await builder.restoreWithProgress()).awaitSandbox();
      expect(native.controls).not.toHaveBeenCalled();
      expect(native.create).not.toHaveBeenCalled();
    });
    for (const seed of [
      "group:baseline",
      { reference: "cloud-snapshot-id", referenceKind: "id" as const },
      { reference: "/snapshots/baseline", referenceKind: "path" as const },
    ]) {
      for (const ownsLifecycle of [false, true]) {
        it(`${method} preserves ${typeof seed === "string" ? "auto" : seed.referenceKind} seeds and lifecycle ownership (${ownsLifecycle})`, async () => {
          native.ownsLifecycle = ownsLifecycle;
          const builder = Sandbox.restore(seed).name("restored");
          expect(native.restoreSeed).toHaveBeenCalledWith(
            typeof seed === "string" ? seed : seed.reference,
            typeof seed === "string" ? undefined : seed.referenceKind,
          );
          const sandbox = method === "restore"
            ? await builder.restore()
            : await (await builder.restoreWithProgress()).awaitSandbox();

          // A full restore can auto-detach; disposal must not acquire lifecycle ownership.
          expect(sandbox.ownsLifecycle).toBe(ownsLifecycle);
          expect(sandbox.id).toBe("restored-id");
          expect(native.restore).toHaveBeenCalledTimes(method === "restore" ? 1 : 0);
          expect(native.create).not.toHaveBeenCalled();
          await sandbox[Symbol.asyncDispose]();
          expect(native.stop).toHaveBeenCalledTimes(ownsLifecycle ? 1 : 0);
        });
      }
    }
  }
});
