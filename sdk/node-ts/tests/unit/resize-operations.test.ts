import { describe, expect, it, vi } from "vitest";
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import { modificationResultFromJson, resizeOperationsFromJson, resizeOperationsToJson } from "../../dist/resize.js";

const max = "18446744073709551615";
const wire = {
  id: "operation-a", runtime_boot_id: "run-a", generation: max,
  requested_target: { resource: "memory", total_mib: max },
  accepted_target: { resource: "memory", total_mib: "514" },
  status: { resource: "memory", requested: "514 MiB", actual: "256 MiB", enforced: "256 MiB", state: "converging" },
  outcome: "pending", observation: "paused",
};
const plan = { sandbox: "test", status: "running", applied: true, policy: "no_restart", changes: [], conflicts: [], warnings: [] };

it("round trips full-width identities and targets without floating-point conversion", () => {
  const records = resizeOperationsFromJson(JSON.stringify([wire]));
  expect(records[0].generation).toBe((1n << 64n) - 1n);
  expect(records[0].requestedTarget).toEqual({ resource: "memory", totalMib: (1n << 64n) - 1n });
  expect(JSON.parse(resizeOperationsToJson(records))).toEqual([wire]);
  expect(resizeOperationsFromJson("[]")).toEqual([]);
});

it("does not reinterpret unavailable tracking as an empty successful wait", () => {
  const result = modificationResultFromJson(JSON.stringify({ plan, resize_operations: null }));
  expect(result.plan.applied).toBe(true);
  expect(result.resizeOperations).toBeNull();
  expect(() => resizeOperationsToJson([])).toThrow("one or two");
});

it("rejects rounded or out-of-range generations in both directions", () => {
  for (const value of [Number(max), -1n, 1n << 64n]) {
    const records = resizeOperationsFromJson(JSON.stringify([wire]));
    (records[0] as any).generation = value;
    expect(() => resizeOperationsToJson(records)).toThrow("unsigned 64-bit bigint");
  }
  for (const value of [Number(max), "-1", "01", "18446744073709551616"]) {
    expect(() => resizeOperationsFromJson(JSON.stringify([{ ...wire, generation: value }]))).toThrow();
  }
});

for (const kind of ["sandbox", "handle"] as const) {
  describe(`${kind} operation dispatch`, () => {
    const wrap = (native: any) => kind === "sandbox" ? new Sandbox(native, "test") : new SandboxHandle(native);
    it("preserves modify options and exact records across apply, read and wait", async () => {
      const native = {
        modifyWithResizeTracking: vi.fn().mockResolvedValue(JSON.stringify({ plan, resize_operations: [wire] })),
        resizeOperations: vi.fn().mockResolvedValue(JSON.stringify([wire])),
        waitForResizeOperations: vi.fn().mockResolvedValue(JSON.stringify([wire.status])),
      };
      const receiver = wrap(native);
      const result = await receiver.modifyWithResizeTracking({ memory: 514, labels: { purpose: "test" } });
      expect(native.modifyWithResizeTracking).toHaveBeenCalledOnce();
      expect(native.modifyWithResizeTracking.mock.calls[0][0]).toMatchObject({ memoryMib: 514, labels: { purpose: "test" } });
      expect(await receiver.resizeOperations()).toEqual(result.resizeOperations);
      expect(await receiver.waitForResizeOperations(result.resizeOperations!, 25)).toEqual([wire.status]);
      expect(native.waitForResizeOperations).toHaveBeenCalledWith(JSON.stringify([wire]), 25);
    });
    it("refuses missing native support before mutation and keeps ordinary modify usable", async () => {
      const native = { modify: vi.fn().mockResolvedValue(JSON.stringify(plan)) };
      const receiver = wrap(native);
      await expect(receiver.modifyWithResizeTracking({ cpus: 2 })).rejects.toThrow("updated native library");
      await expect(receiver.resizeOperations()).rejects.toThrow("updated native library");
      await expect(receiver.waitForResizeOperations(resizeOperationsFromJson(JSON.stringify([wire])))).rejects.toThrow("updated native library");
      expect(native.modify).not.toHaveBeenCalled();
      expect((await receiver.modify({ cpus: 2 })).applied).toBe(true);
      expect(native.modify).toHaveBeenCalledOnce();
    });
    it("does not retry a failed dispatched modification through the original API", async () => {
      const native = { modify: vi.fn(), modifyWithResizeTracking: vi.fn().mockRejectedValue(new Error("reply lost")) };
      await expect(wrap(native).modifyWithResizeTracking({ cpus: 2 })).rejects.toThrow("reply lost");
      expect(native.modifyWithResizeTracking).toHaveBeenCalledOnce();
      expect(native.modify).not.toHaveBeenCalled();
    });
    it("rejects invalid identities and wait budgets before dispatch", async () => {
      const native = { waitForResizeOperations: vi.fn() };
      const receiver = wrap(native);
      await expect(receiver.waitForResizeOperations([])).rejects.toThrow();
      await expect(receiver.waitForResizeOperations(resizeOperationsFromJson(JSON.stringify([wire])), -1)).rejects.toThrow();
      expect(native.waitForResizeOperations).not.toHaveBeenCalled();
    });
  });
}
