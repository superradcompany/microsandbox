import { describe, expect, it } from "vitest";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
  resizeStatusFromJson,
  validateResizeTimeout,
} from "../../dist/modify.js";

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

describe("resizeStatusFromJson", () => {
  it("parses the native resize status array", () => {
    const status = resizeStatusFromJson(
      JSON.stringify([
        { resource: "cpus", requested: "4", actual: "2", enforced: "4", state: "converging" },
        { resource: "memory", requested: "8 GiB", actual: "8 GiB", enforced: "8 GiB", state: "applied" },
      ]),
    );
    expect(status.map((entry) => [entry.resource, entry.state])).toEqual([
      ["cpus", "converging"],
      ["memory", "applied"],
    ]);
    expect(resizeStatusFromJson("[]")).toEqual([]);
  });

  it("rejects timeouts N-API cannot represent", () => {
    expect(() => validateResizeTimeout(undefined)).not.toThrow();
    expect(() => validateResizeTimeout(0)).not.toThrow();
    expect(() => validateResizeTimeout(1500)).not.toThrow();
    for (const value of [-1, NaN, Infinity]) {
      expect(() => validateResizeTimeout(value)).toThrow(RangeError);
    }
  });
});
