import { beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({ storageUsage: vi.fn(), storagePrune: vi.fn() }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: native }));

import { Storage } from "../../dist/storage.js";
import { IoError, UnsupportedError, UnsupportedOperationError } from "../../dist/errors.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import { Snapshot } from "../../dist/snapshot.js";
import { SnapshotHandle } from "../../dist/snapshot-handle.js";

const category = () => ({
  count: undefined, inUse: undefined, logicalBytes: undefined,
  allocatedBytes: undefined, reclaimableLogicalBytes: undefined, items: [], notes: [],
});
const usage = () => ({
  images: category(), snapshots: category(), sandboxes: category(), volumes: category(),
  branchMemory: category(), snapshotMemory: category(), notes: ["Logical accounting"],
});
const prune = () => ({
  dryRun: false, entries: [], filesRemoved: 0, logicalBytesRemoved: 0n,
  physicalBytesReclaimed: undefined, truncated: false,
});

beforeEach(() => {
  vi.resetAllMocks();
  native.storageUsage.mockResolvedValue(usage());
  native.storagePrune.mockResolvedValue(prune());
});

describe("Storage", () => {
  it("preserves unknowns, zero measurements, and per-object retention explanations", async () => {
    native.storageUsage.mockResolvedValue({
      ...usage(),
      branchMemory: {
        ...category(), count: 1, logicalBytes: 0n, reclaimableLogicalBytes: 0n,
        items: [{ name: "branch", path: "/cache/branch.ram", logicalBytes: 0n,
          allocatedBytes: undefined, inUse: false, reclaimable: undefined,
          reasons: ["missing handoff lock"] }],
      },
    });
    const report = await Storage.usage();
    expect(report.images.logicalBytes).toBeNull();
    expect(report.branchMemory.logicalBytes).toBe(0n);
    expect(report.branchMemory.items[0]).toEqual({
      name: "branch", path: "/cache/branch.ram", logicalBytes: 0n,
      allocatedBytes: null, inUse: false, reclaimable: null,
      reasons: ["missing handoff lock"],
    });
    expect(report.notes).toEqual(["Logical accounting"]);
  });

  it("forwards preview and age options without conflating preview bytes with removal", async () => {
    native.storagePrune.mockResolvedValue({
      ...prune(), dryRun: true,
      entries: [{ path: "/cache/branch.ram", kind: "branch_memory", logicalBytes: 4096n,
        allocatedBytes: 512n, state: "reclaimable", error: undefined }],
    });
    const report = await Storage.prune({ dryRun: true, olderThanSeconds: 3600 });
    expect(native.storagePrune).toHaveBeenCalledWith(true, 3600);
    expect(report.filesRemoved).toBe(0);
    expect(report.logicalBytesRemoved).toBe(0n);
    expect(report.physicalBytesReclaimed).toBeNull();
    expect(report.entries[0]?.logicalBytes).toBe(4096n);
    expect(report.entries[0]?.error).toBeNull();
    await Storage.prune();
    expect(native.storagePrune).toHaveBeenLastCalledWith(undefined, undefined);
  });

  it("retains partial cleanup errors alongside completed removals", async () => {
    native.storagePrune.mockResolvedValue({
      ...prune(), filesRemoved: 1, logicalBytesRemoved: 4096n,
      entries: [{ path: "/cache/failure.ram", kind: "snapshot_memory", logicalBytes: undefined,
        allocatedBytes: undefined, state: "error", error: "permission denied" }],
    });
    const report = await Storage.prune();
    expect(report.logicalBytesRemoved).toBe(4096n);
    expect(report.entries[0]?.state).toBe("error");
    expect(report.entries[0]?.error).toBe("permission denied");
    expect(report.entries[0]?.logicalBytes).toBeNull();
  });

  it("rejects invalid options before invoking native deletion", async () => {
    for (const olderThanSeconds of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(Storage.prune({ olderThanSeconds })).rejects.toThrow("safe integer");
    }
    await expect(Storage.prune({ dryRun: "yes" as unknown as boolean })).rejects.toThrow("boolean");
    expect(native.storagePrune).not.toHaveBeenCalled();
  });

  it("preserves full-width bytes after deletion without losing the report", async () => {
    const maximum = 2n ** 64n - 1n;
    native.storageUsage.mockResolvedValue({
      ...usage(), images: { ...category(), logicalBytes: maximum, allocatedBytes: 0n },
    });
    const observed = await Storage.usage();
    expect(observed.images.logicalBytes).toBe(maximum);
    expect(observed.images.allocatedBytes).toBe(0n);
    native.storagePrune.mockResolvedValue({
      ...prune(), filesRemoved: 1, logicalBytesRemoved: maximum,
      entries: [{ path: "/cache/huge.ram", kind: "branch_memory", logicalBytes: maximum,
        allocatedBytes: 4096n, state: "removed", error: undefined }],
    });
    const result = await Storage.prune();
    expect(result.logicalBytesRemoved).toBe(maximum);
    expect(result.entries[0]?.logicalBytes).toBe(maximum);
    expect(result.filesRemoved).toBe(1);
  });

  it("rejects unsafe object counts instead of rounding them", async () => {
    native.storageUsage.mockResolvedValue({
      ...usage(), images: { ...category(), count: Number.MAX_SAFE_INTEGER + 1 },
    });
    await expect(Storage.usage()).rejects.toThrow("safe integer");
  });

  it("reports unsupported operations when an older addon lacks storage exports", async () => {
    const existing = { ...native };
    Object.assign(native, { storageUsage: undefined, storagePrune: undefined });
    try {
      await expect(Storage.usage()).rejects.toBeInstanceOf(UnsupportedOperationError);
      await expect(Storage.prune()).rejects.toMatchObject({
        code: "unsupportedOperation",
        message: expect.stringContaining("upgrade or rebuild"),
      });
    } finally {
      Object.assign(native, existing);
    }
    expect(native.storageUsage).not.toHaveBeenCalled();
    expect(native.storagePrune).not.toHaveBeenCalled();
  });

  it("maps backend and filesystem failures through the existing error API", async () => {
    native.storageUsage.mockRejectedValue(new Error("[Unsupported] storage requires a local backend"));
    await expect(Storage.usage()).rejects.toBeInstanceOf(UnsupportedError);
    native.storagePrune.mockRejectedValue(new Error("[Io] inaccessible memory namespace"));
    await expect(Storage.prune()).rejects.toBeInstanceOf(IoError);
  });

  it.each([
    ["SandboxHandle", (inner: never) => new SandboxHandle(inner)],
    ["Snapshot", (inner: never) => new Snapshot(inner)],
    ["SnapshotHandle", (inner: never) => new SnapshotHandle(inner)],
  ] as const)("observes %s through its native receiver", async (_name, wrap) => {
    const item = {
      name: "artifact", path: "/captured/artifact", logicalBytes: 2n ** 64n - 1n,
      allocatedBytes: undefined, inUse: false, reclaimable: undefined,
      reasons: ["durable artifact"],
    };
    const storageUsage = vi.fn(function (this: unknown) {
      expect(this).toBe(inner);
      return Promise.resolve(item);
    });
    const inner = { storageUsage, open: vi.fn() };
    const handle = wrap(inner as never);
    expect(await handle.storageUsage()).toEqual({
      ...item, allocatedBytes: null, reclaimable: null,
    });
    expect(native.storageUsage).not.toHaveBeenCalled();
    storageUsage.mockRejectedValue(new Error("[Unsupported] remote artifact storage unavailable"));
    await expect(handle.storageUsage()).rejects.toBeInstanceOf(UnsupportedError);
  });

  it("rejects unsupported old handles and metadata-only snapshot list records", async () => {
    await expect(new SandboxHandle({} as never).storageUsage())
      .rejects.toBeInstanceOf(UnsupportedOperationError);
    await expect(new Snapshot({} as never).storageUsage())
      .rejects.toBeInstanceOf(UnsupportedOperationError);
    await expect(new SnapshotHandle({ open: vi.fn() } as never).storageUsage())
      .rejects.toThrow("upgrade or rebuild");
    await expect(new SnapshotHandle({} as never).storageUsage())
      .rejects.toThrow("Snapshot.get()");
    expect(native.storageUsage).not.toHaveBeenCalled();
  });
});
