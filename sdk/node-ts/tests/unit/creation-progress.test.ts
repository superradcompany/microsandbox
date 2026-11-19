import { beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({
  ownsLifecycle: false,
  backendKind: "local" as "local" | "cloud",
  detach: vi.fn(async () => {}),
  ensureRunning: vi.fn(async () => {}),
  requestedDetached: undefined as boolean | undefined,
  stop: vi.fn(async () => {}),
  shutdownOwned: vi.fn(async () => {}),
  cancel: vi.fn(),
  create: vi.fn(),
  restoreSeed: vi.fn(),
  restore: vi.fn(),
  controls: vi.fn(),
}));

vi.mock("../../dist/internal/napi.js", () => {
  const sandbox = () => ({
    id: "restored-id",
    backendKind: native.backendKind,
    detach: native.detach,
    ensureRunning: native.ensureRunning,
    get ownsLifecycle() { return native.ownsLifecycle; },
    shutdownOwned: native.shutdownOwned,
    stop: native.stop,
  });
  const progress = () => ({
    cancel: native.cancel,
    progress: {},
    awaitSandbox: async () => sandbox(),
  });
  return {
    napi: {
      Sandbox: {
        get: async () => sandbox(),
        getRunning: async () => sandbox(),
        start: async () => sandbox(),
        startDetached: async () => sandbox(),
      },
      SandboxBuilder: class {
        detached(enabled: boolean): this {
          native.requestedDetached = enabled;
          return this;
        }
        async create() {
          native.create();
          return sandbox();
        }
        async connectOrCreate() { return sandbox(); }
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
        maxDurationSeconds(value: number): this { native.controls("maxDurationSeconds", value); return this; }
        idleTimeoutSeconds(value: number): this { native.controls("idleTimeoutSeconds", value); return this; }
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
    native.backendKind = "local";
    native.detach.mockClear();
    native.requestedDetached = undefined;
    native.stop.mockReset();
    native.shutdownOwned.mockReset();
    native.detach.mockImplementation(async () => { native.ownsLifecycle = false; });
    native.cancel.mockClear();
    native.create.mockClear();
    native.restoreSeed.mockClear();
    native.restore.mockClear();
    native.controls.mockClear();
  });

  it("detach remains usable, repeatable and updates ownership", async () => {
    native.ownsLifecycle = true;
    const sandbox = await Sandbox.builder("detach").create();
    await sandbox.detach();
    await sandbox.detach();
    expect(sandbox.ownsLifecycle).toBe(false);
    expect(sandbox.id).toBe("restored-id");
    await sandbox[Symbol.asyncDispose]();
    expect(native.shutdownOwned).not.toHaveBeenCalled();
    await sandbox.stop();
    expect(native.stop).toHaveBeenCalledOnce();
  });

  it("failed detach keeps cleanup authority and exposes the error", async () => {
    native.ownsLifecycle = true;
    native.detach.mockRejectedValueOnce(new Error("detach failed"));
    const sandbox = await Sandbox.builder("detach-failure").create();
    await expect(sandbox.detach()).rejects.toThrow("detach failed");
    expect(sandbox.ownsLifecycle).toBe(true);
    await sandbox[Symbol.asyncDispose]();
    expect(native.shutdownOwned).toHaveBeenCalledOnce();
  });

  it("reports scope cleanup errors", async () => {
    native.ownsLifecycle = true;
    native.shutdownOwned.mockRejectedValueOnce(new Error("cleanup failed"));
    const sandbox = await Sandbox.builder("cleanup-failure").create();
    await expect(sandbox[Symbol.asyncDispose]()).rejects.toThrow("cleanup failed");
  });

  it("preserves body and cleanup failures from await-using", async () => {
    native.ownsLifecycle = true;
    const body = new Error("body failed");
    const cleanup = new Error("cleanup failed");
    native.shutdownOwned.mockRejectedValueOnce(cleanup);
    try {
      await using sandbox = await Sandbox.builder("both-fail").create();
      expect(sandbox.ownsLifecycle).toBe(true);
      throw body;
    } catch (error) {
      expect(error).toMatchObject({ error: cleanup, suppressed: body });
      return;
    }
    throw new Error("expected both failures");
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
        expect(native.shutdownOwned).toHaveBeenCalledTimes(ownsLifecycle ? 1 : 0);
      });
    }
  }

  for (const method of ["start", "startDetached", "getRunning"] as const) {
    for (const ownsLifecycle of [false, true]) {
      it(`${method} preserves actual local ownership (${ownsLifecycle})`, async () => {
        native.ownsLifecycle = ownsLifecycle;
        const sandbox = await Sandbox[method]("local-start");
        expect(sandbox.ownsLifecycle).toBe(ownsLifecycle);
        await sandbox[Symbol.asyncDispose]();
        expect(native.shutdownOwned).toHaveBeenCalledTimes(ownsLifecycle ? 1 : 0);
      });
    }
  }

  for (const method of ["restore", "restoreWithProgress"] as const) {
    it(`${method} retains explicit destination controls and zero limits`, async () => {
      const policy = { defaultEgress: "deny" as const, defaultIngress: "deny" as const, rules: [] };
      const builder = Sandbox.restore("baseline").name("destination")
        .cpus(2).memory(512).networkPolicy(policy).maxTcpConnections(0).maxUdpConnections(7)
        .disableNetwork().security("default").maxDurationSeconds(0).idleTimeoutSeconds(0);
      if (method === "restore") await builder.restore();
      else await (await builder.restoreWithProgress()).awaitSandbox();
      expect(native.controls.mock.calls).toEqual([
        ["cpus", 2], ["memory", 512], ["networkPolicy", policy],
        ["maxTcpConnections", 0], ["maxUdpConnections", 7],
        ["disableNetwork"], ["security", "default"], ["maxDurationSeconds", 0], ["idleTimeoutSeconds", 0],
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
          expect(native.shutdownOwned).toHaveBeenCalledTimes(ownsLifecycle ? 1 : 0);
        });
      }
    }
  }
});


describe("cloud scope cleanup", () => {
  beforeEach(() => {
    native.backendKind = "cloud";
    native.ownsLifecycle = false;
    native.stop.mockReset();
    native.shutdownOwned.mockReset();
    native.detach.mockImplementation(async () => { native.ownsLifecycle = false; });
    native.detach.mockClear();
  });

  for (const method of ["create", "createWithProgress", "createWithPullProgress"] as const) {
    for (const detached of [undefined, false, true]) {
      it(`${method} scopes remote creation with detached=${detached}`, async () => {
        const builder = Sandbox.builder("cloud-scope");
        if (detached !== undefined) builder.detached(detached);
        {
          await using sandbox = method === "create"
            ? await builder.create()
            : await (await builder[method]()).awaitSandbox();
          expect(sandbox.ownsLifecycle).toBe(!detached);
          expect(native.stop).not.toHaveBeenCalled();
        }
        expect(native.stop).toHaveBeenCalledTimes(detached ? 0 : 1);
        expect(native.shutdownOwned).not.toHaveBeenCalled();
      });
    }
  }

  for (const method of ["get", "start", "startDetached", "getRunning"] as const) {
    it(`${method} does not acquire remote scope ownership`, async () => {
      const sandbox = await Sandbox[method]("existing-cloud");
      expect(sandbox.ownsLifecycle).toBe(false);
      await sandbox[Symbol.asyncDispose]();
      expect(native.stop).not.toHaveBeenCalled();
    });
  }

  it("explicit stop still reaches the remote sandbox", async () => {
    const sandbox = await Sandbox.builder("cloud-explicit-stop").create();
    await sandbox.stop();
    expect(native.stop).toHaveBeenCalledTimes(1);
  });

  it("attempts remote stop on exceptional exit and preserves the body error", async () => {
    native.stop.mockRejectedValueOnce(new Error("provider unavailable"));
    await expect((async () => {
      await using sandbox = await Sandbox.builder("cloud-error").create();
      throw new Error("guest failed");
    })()).rejects.toThrow("guest failed");
    expect(native.stop).toHaveBeenCalledOnce();
  });

  it("awaits remote stop even when the provider eventually rejects it", async () => {
    const stop = Promise.withResolvers<void>();
    native.stop.mockReturnValueOnce(stop.promise);
    let exited = false;
    const scope = (async () => {
      await using sandbox = await Sandbox.builder("cloud-stop").create();
      expect(sandbox.ownsLifecycle).toBe(true);
    })().then(() => { exited = true; });
    await vi.waitFor(() => expect(native.stop).toHaveBeenCalledOnce());
    expect(exited).toBe(false);
    stop.reject(new Error("provider unavailable"));
    await scope;
    expect(exited).toBe(true);
  });

  it("keeps remote cleanup armed when detach fails", async () => {
    native.detach.mockRejectedValueOnce(new Error("detach failed"));
    {
      await using sandbox = await Sandbox.builder("cloud-detach-failure").create();
      await expect(sandbox.detach()).rejects.toThrow("detach failed");
      expect(sandbox.ownsLifecycle).toBe(true);
    }
    expect(native.stop).toHaveBeenCalledOnce();
  });

  it("honors detaching a created handle", async () => {
    const sandbox = await Sandbox.builder("cloud-detach").create();
    await sandbox.detach();
    await sandbox[Symbol.asyncDispose]();
    expect(native.detach).toHaveBeenCalledTimes(1);
    expect(native.stop).not.toHaveBeenCalled();
  });

  it("does not acquire ownership of connected cloud handles", async () => {
    const sandbox = await Sandbox.builder("existing-cloud").connectOrCreate();
    expect(sandbox.ownsLifecycle).toBe(false);
    await sandbox[Symbol.asyncDispose]();
    expect(native.stop).not.toHaveBeenCalled();
  });
});


describe("unified Sandbox lookup", () => {
  it("returns a usable resource without preparing until requested", async () => {
    const sandbox = await Sandbox.get("task");
    expect(sandbox).toBeInstanceOf(Sandbox);
    expect(sandbox.id).toBe("restored-id");
    expect(native.ensureRunning).not.toHaveBeenCalled();
    await sandbox.ensureRunning();
    expect(native.ensureRunning).toHaveBeenCalledTimes(1);
  });
});
