import { afterEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({}) as { supportsSecretPolicyModification?: () => boolean });
vi.mock("../../dist/internal/napi.js", () => ({ napi: native }));
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
  type ModifyOptions,
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

  it("rejects unknown secret spec keys without echoing their values", () => {
    const opts = {
      secrets: { API_KEY: { value: "dummy-secret", allowedHost: ["api.example.com"] } },
    } as unknown as ModifyOptions;

    expect(() => modifyOptionsToNapi(opts)).toThrow(
      'secret "API_KEY": unknown key "allowedHost"; expected one of "env", "value", ' +
        '"store", "placeholder", "allowedHosts", "substitution", "violationAction", ' +
        '"requireTlsIdentity", "allowPlaceholderFor"',
    );
    expect(() => modifyOptionsToNapi(opts)).not.toThrow(/dummy-secret|api\.example\.com/);
  });

  it("rejects unknown substitution keys", () => {
    const opts = {
      secrets: { API_KEY: { substitution: { header_fields: ["authorization"] } } },
    } as unknown as ModifyOptions;

    expect(() => modifyOptionsToNapi(opts)).toThrow(
      'secret "API_KEY": unknown key "substitution.header_fields"; expected one of ' +
        '"substitution.headers", "substitution.headerFields", "substitution.query", ' +
        '"substitution.body"',
    );
  });

  it("ignores unknown keys whose value is undefined", () => {
    const opts = {
      secrets: { API_KEY: { env: "HOST_KEY", stale: undefined, substitution: { old: undefined } } },
    } as unknown as ModifyOptions;

    expect(() => modifyOptionsToNapi(opts)).not.toThrow();
  });
});

describe("secret policy capability gate", () => {
  const plan = JSON.stringify({ sandbox: "api", status: "running", applied: false, policy: "restart" });
  const policyFields: ModifyOptions["secrets"][] = [
    { API_KEY: { substitution: { headerFields: ["authorization"] } } },
    { API_KEY: { violationAction: "block" } },
    { API_KEY: { requireTlsIdentity: false } },
    { API_KEY: { allowPlaceholderFor: ["api.anthropic.com"] } },
  ];

  function targets() {
    const modify = vi.fn(async () => plan);
    return {
      modify,
      sandbox: new Sandbox({ modify } as unknown as NapiSandbox, "api"),
      handle: new SandboxHandle({ modify } as unknown as NapiSandboxHandle),
    };
  }

  afterEach(() => {
    delete native.supportsSecretPolicyModification;
  });

  it("refuses policy fields when the native library lacks the marker", async () => {
    const { modify, sandbox, handle } = targets();
    for (const secrets of policyFields) {
      for (const target of [sandbox, handle]) {
        await expect(target.modify({ secrets, policy: "restart" })).rejects.toThrow(
          "secret policy modification requires an updated native library",
        );
      }
    }
    expect(modify).not.toHaveBeenCalled();
  });

  it("forwards policy fields when the native library has the marker", async () => {
    native.supportsSecretPolicyModification = () => true;
    const { modify, sandbox, handle } = targets();
    for (const target of [sandbox, handle]) {
      await target.modify({ secrets: policyFields[0], policy: "restart" });
    }
    expect(modify).toHaveBeenCalledTimes(2);
  });

  it("does not need the marker for specs that change no policy", async () => {
    const { modify, sandbox, handle } = targets();
    for (const target of [sandbox, handle]) {
      await target.modify({ secrets: { API_KEY: { env: "HOST_KEY", allowPlaceholderFor: [] } } });
    }
    expect(modify).toHaveBeenCalledTimes(2);
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
