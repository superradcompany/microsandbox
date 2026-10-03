import { afterEach, describe, expect, it, vi } from "vitest";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
} from "../../dist/modify.js";
import { UnsupportedOperationError } from "../../dist/errors.js";
import { napi } from "../../dist/internal/napi.js";
import type { NapiSandbox, NapiSandboxHandle } from "../../dist/internal/napi.js";
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";

describe("modifyOptionsToNapi", () => {
  it("returns undefined for omitted options", () => {
    expect(modifyOptionsToNapi(undefined)).toBeUndefined();
  });

  it("maps memory and disk sizes onto the MiB native fields", () => {
    expect(
      modifyOptionsToNapi({
        cpus: 2,
        maxCpus: 8,
        memory: 1024,
        maxMemory: 4096,
        rootDiskSize: 8192,
        env: { API_URL: "https://api" },
        envRemove: ["OLD"],
        labels: { tier: "gold" },
        labelsRemove: ["stale"],
        workdir: "/srv",
        policy: "next_start",
        dryRun: true,
      }),
    ).toEqual({
      cpus: 2,
      maxCpus: 8,
      memoryMib: 1024,
      maxMemoryMib: 4096,
      rootDiskSizeMib: 8192,
      env: { API_URL: "https://api" },
      envRemove: ["OLD"],
      labels: { tier: "gold" },
      labelsRemove: ["stale"],
      workdir: "/srv",
      secrets: undefined,
      secretsRemove: undefined,
      policy: "next_start",
      dryRun: true,
    });
  });

  it("passes secret specs and removals through to the native layer", () => {
    const napi = modifyOptionsToNapi({
      secrets: {
        API_KEY: {
          env: "HOST_API_KEY",
          placeholder: "$API_KEY",
          allowedHosts: ["api.example.com"],
        },
        DB_PASS: { store: "vault://prod/db" },
        STRIPE_KEY: { value: "sk_test_123" },
      },
      secretsRemove: ["OLD"],
    });

    expect(napi?.secrets).toEqual({
      API_KEY: {
        env: "HOST_API_KEY",
        placeholder: "$API_KEY",
        allowedHosts: ["api.example.com"],
      },
      DB_PASS: { store: "vault://prod/db" },
      STRIPE_KEY: { value: "sk_test_123" },
    });
    expect(napi?.secretsRemove).toEqual(["OLD"]);
  });

  it("passes mounts and removals through to the native layer", () => {
    const mount = {
      kind: "bind",
      guest: "/data",
      readonly: true,
      noexec: false,
      nosuid: false,
      nodev: false,
      host: "/srv/data",
    } as const;
    const napi = modifyOptionsToNapi({
      mounts: [mount],
      mountsRemove: ["/old"],
    });

    expect(napi?.mounts).toEqual([mount]);
    expect(napi?.mountsRemove).toEqual(["/old"]);
  });
});

describe("modificationPlanFromJson", () => {
  it("parses the canonical plan JSON emitted by the native layer", () => {
    const plan = modificationPlanFromJson(
      JSON.stringify({
        sandbox: "api",
        status: "running",
        applied: false,
        policy: "no_restart",
        changes: [
          {
            kind: "config",
            field: "cpus",
            change: "updated",
            before: "2",
            after: "4",
            disposition: "live",
          },
          {
            kind: "secret",
            field: "secret",
            name: "API_KEY",
            change: "rotated",
            before_ref: "$API_KEY",
            after_ref: "$API_KEY",
            disposition: "requires restart",
            allow_hosts: ["api.example.com"],
            reason: "live secret reconfiguration is not available",
          },
        ],
        conflicts: [{ field: "memory", message: "memory must be greater than 0" }],
        warnings: [{ field: "cpus", message: "warning" }],
      }),
    );

    expect(plan.sandbox).toBe("api");
    expect(plan.applied).toBe(false);
    expect(plan.policy).toBe("no_restart");
    expect(plan.changes).toEqual([
      {
        kind: "config",
        field: "cpus",
        change: "updated",
        before: "2",
        after: "4",
        disposition: "live",
        reason: undefined,
      },
      {
        kind: "secret",
        field: "secret",
        name: "API_KEY",
        change: "rotated",
        beforeRef: "$API_KEY",
        afterRef: "$API_KEY",
        disposition: "requires restart",
        allowHosts: ["api.example.com"],
        reason: "live secret reconfiguration is not available",
      },
    ]);
    expect(plan.conflicts).toEqual([
      { field: "memory", message: "memory must be greater than 0" },
    ]);
    expect(plan.warnings).toEqual([{ field: "cpus", message: "warning" }]);
    // `resize_status` is omitted from the wire format when empty.
    expect(plan.resizeStatus).toEqual([]);
  });
});

describe("modify mounts native capability", () => {
  const native = napi as { supportsModifyMounts?: () => boolean };
  const original = native.supportsModifyMounts;
  const plan = JSON.stringify({ sandbox: "api", status: "stopped", applied: true });
  const mount = {
    kind: "tmpfs", guest: "/scratch", readonly: false, noexec: false, nosuid: false, nodev: false,
  } as const;

  afterEach(() => {
    native.supportsModifyMounts = original;
  });

  it("refuses a mixed mount and env request before dispatch on an older native addon", async () => {
    native.supportsModifyMounts = undefined;
    const modify = vi.fn(async () => plan);
    const sandbox = new Sandbox({ modify } as unknown as NapiSandbox, "api");
    const handle = new SandboxHandle({ modify } as unknown as NapiSandboxHandle);
    const mixed = { env: { A: "1" }, mounts: [mount] };
    const removal = { env: { A: "1" }, mountsRemove: ["/old"] };

    for (const call of [
      () => sandbox.modify(mixed),
      () => sandbox.modify(removal),
      () => handle.modify(mixed),
      () => handle.modify(removal),
    ]) {
      await expect(call()).rejects.toThrow(UnsupportedOperationError);
    }
    expect(modify).not.toHaveBeenCalled();
  });

  it("still dispatches ordinary and mount requests when the capability is present", async () => {
    const modify = vi.fn(async () => plan);
    const sandbox = new Sandbox({ modify } as unknown as NapiSandbox, "api");

    native.supportsModifyMounts = undefined;
    await sandbox.modify({ env: { A: "1" }, mounts: [] });
    expect(modify).toHaveBeenCalledTimes(1);

    native.supportsModifyMounts = () => true;
    await sandbox.modify({ mounts: [mount] });
    expect(modify).toHaveBeenCalledTimes(2);
  });
});
