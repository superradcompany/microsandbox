import { describe, expect, it } from "vitest";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
} from "../../dist/modify.js";

describe("modifyOptionsToNapi", () => {
  it("returns undefined for omitted options", () => {
    expect(modifyOptionsToNapi(undefined)).toBeUndefined();
  });

  it("maps memory/maxMemory onto the MiB native fields", () => {
    expect(
      modifyOptionsToNapi({
        cpus: 2,
        maxCpus: 8,
        memory: 1024,
        maxMemory: 4096,
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
      env: { API_URL: "https://api" },
      envRemove: ["OLD"],
      labels: { tier: "gold" },
      labelsRemove: ["stale"],
      workdir: "/srv",
      policy: "next_start",
      dryRun: true,
    });
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
