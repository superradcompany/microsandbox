import { describe, expect, it, vi } from "vitest";
import { Snapshot as Checkpoint } from "../../dist/snapshot.js";
import { SnapshotRemovalRecoveryError, UnsupportedError } from "../../dist/errors.js";

vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
vi.mock("../../dist/sandbox.js", () => ({ Sandbox: class {} }));

const result = { id: "removed", head_update: { group: "history", previous: "removed", head: "parent", reason: "parent_fallback", changed: true }, warnings: [] };

describe("exact checkpoint removal", () => {
  it("returns the operation's head outcome without querying current head", async () => {
    const removeCheckpoint = vi.fn().mockResolvedValue(JSON.stringify(result));
    const checkpoint = new Checkpoint({ removeCheckpoint } as never);
    expect(await checkpoint.remove()).toEqual({ id: "removed", headUpdate: result.head_update, warnings: [] });
    expect(removeCheckpoint).toHaveBeenCalledWith(false);
    await checkpoint.removeWith(options => options.force());
    expect(removeCheckpoint).toHaveBeenLastCalledWith(true);
  });

  it("retains the committed report when cleanup fails", async () => {
    const raw = new Error(`[SnapshotRemovalRecovery] ${JSON.stringify({message: "removal committed; cleanup failed", result, detail: "catalog unavailable"})}`);
    const checkpoint = new Checkpoint({ removeCheckpoint: vi.fn().mockRejectedValue(raw) } as never);
    const error = await checkpoint.remove().catch(error => error);
    expect(error).toBeInstanceOf(SnapshotRemovalRecoveryError);
    expect(error.result.id).toBe("removed");
    expect(error.result.headUpdate.head).toBe("parent");
    expect(error.detail).toBe("catalog unavailable");
    expect(error.cause).toBe(raw);
  });

  it("does not fall back to reference deletion on older native libraries", async () => {
    await expect(new Checkpoint({} as never).remove()).rejects.toBeInstanceOf(UnsupportedError);
  });

  it("refuses malformed reports rather than manufacturing a head outcome", async () => {
    const checkpoint = new Checkpoint({ removeCheckpoint: vi.fn().mockResolvedValue(JSON.stringify({ id: "removed", warnings: [] })) } as never);
    await expect(checkpoint.remove()).rejects.toThrow("Invalid checkpoint removal head outcome");
  });
});

describe("whole-group removal", () => {
  const result = { group: "history", removed: ["parent", "child"], head_update: { group: "history", previous: "child", head: null, reason: "cleared", changed: true }, warnings: [] };
  it("returns every removed identity and this operation's head outcome", async () => {
    const { Snapshot } = await import("../../dist/snapshot-group.js");
    const removeGroup = vi.fn().mockResolvedValue(JSON.stringify(result));
    const group = new Snapshot({ removeGroup } as never);
    expect(await group.remove()).toEqual({ group: "history", removed: ["parent", "child"], headUpdate: result.head_update, warnings: [] });
    expect(removeGroup).toHaveBeenCalledExactlyOnceWith();
  });
  it("preserves committed whole-group failures and the original cause", async () => {
    const { Snapshot } = await import("../../dist/snapshot-group.js");
    const { SnapshotGroupRemovalRecoveryError } = await import("../../dist/errors.js");
    const raw = new Error(`[SnapshotGroupRemovalRecovery] ${JSON.stringify({ message: "group removed; cleanup failed", result, detail: "catalog unavailable" })}`);
    const group = new Snapshot({ removeGroup: vi.fn().mockRejectedValue(raw) } as never);
    const error = await group.remove().catch(error => error);
    expect(error).toBeInstanceOf(SnapshotGroupRemovalRecoveryError);
    expect(error.result.removed).toEqual(["parent", "child"]);
    expect(error.result.headUpdate.head).toBeNull();
    expect(error.detail).toBe("catalog unavailable");
    expect(error.cause).toBe(raw);
  });
  it("refuses old native libraries before attempting mutation", async () => {
    const { Snapshot } = await import("../../dist/snapshot-group.js");
    await expect(new Snapshot({} as never).remove()).rejects.toBeInstanceOf(UnsupportedError);
  });
  it("does not manufacture success from a missing head outcome", async () => {
    const { Snapshot } = await import("../../dist/snapshot-group.js");
    const group = new Snapshot({ removeGroup: vi.fn().mockResolvedValue(JSON.stringify({ ...result, head_update: null })) } as never);
    await expect(group.remove()).rejects.toThrow("Invalid group removal result");
  });
});
