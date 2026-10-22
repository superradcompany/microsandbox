import { describe, expect, it, vi } from "vitest";
import { Snapshot, snapshotCreateResult } from "../../dist/snapshot-group.js";
import { napi } from "../../dist/internal/napi.js";
import { SnapshotVerificationError } from "../../dist/errors.js";

vi.mock("../../dist/internal/napi.js", () => ({
  napi: { SnapshotGroup: { get: vi.fn(), list: vi.fn(), load: vi.fn() }, Snapshot: { groupHead: vi.fn() } },
}));
vi.mock("../../dist/sandbox.js", () => ({ Sandbox: class {} }));

function group(overrides: Record<string, unknown> = {}) {
  return {
    name: "history",
    head: vi.fn().mockResolvedValue(undefined),
    setHead: vi.fn(),
    clearHead: vi.fn().mockResolvedValue({ group: "history", previous: "old", head: undefined, changed: true, reason: "cleared" }),
    checkpoint: vi.fn(),
    ...overrides,
  };
}

describe("group and checkpoint separation", () => {
  it("verifies the whole headless group and preserves empty reporting", async () => {
    const native = group({ verifyJson: vi.fn().mockResolvedValue(JSON.stringify({ group: "history", state: "empty", checkpoints: [], payload_hashes: 0 })) });
    const history = new Snapshot(native as never);
    expect(await history.verify()).toEqual({ group: "history", state: "empty", checkpoints: [], payloadHashes: 0 });
    expect(native.head).not.toHaveBeenCalled();
  });

  it("keeps all member findings when verification rejects", async () => {
    const wire = { group: "history", state: "invalid", payload_hashes: 1, checkpoints: [
      { id: "one", path: "/one", state: "complete", findings: [], report: { digest: "descriptor", path: "/one", upper: { kind: "verified", algorithm: "sha256", digest: "payload" }, checkpoint: null, coverage: { kind: "complete" } } },
      { id: "two", path: "/two", state: "invalid", report: null, findings: [{ path: "/two/disk", kind: "missing", detail: "missing payload" }] },
    ] };
    const raw = new Error(`[SnapshotVerification] ${JSON.stringify({ message: "verification failed", report: wire })}`);
    const history = new Snapshot(group({ verifyJson: vi.fn().mockRejectedValue(raw) }) as never);
    const error = await history.verify().catch(error => error);
    expect(error).toBeInstanceOf(SnapshotVerificationError);
    expect(error.report.payloadHashes).toBe(1);
    expect(error.report.checkpoints[0].report.upper.kind).toBe("verified");
    expect(error.report.checkpoints[1].findings[0].kind).toBe("missing");
    expect(error.cause).toBe(raw);
  });

  it("rejects an unknown report state instead of inferring completeness", async () => {
    const history = new Snapshot(group({ verifyJson: vi.fn().mockResolvedValue(JSON.stringify({ group: "history", state: "future", checkpoints: [], payload_hashes: 0 })) }) as never);
    await expect(history.verify()).rejects.toThrow("invalid native snapshot group verification report");
  });

  it("opens a headless group without manufacturing a checkpoint", async () => {
    const native = group();
    vi.mocked(napi.SnapshotGroup.get).mockResolvedValue(native as never);
    const history = await Snapshot.get("history");
    expect(history.name).toBe("history");
    expect(await history.head()).toBeNull();
    expect(await history.clearHead()).toEqual({ group: "history", previous: "old", head: null, changed: true, reason: "cleared" });
  });

  it("returns the capture's checkpoint even when the current head has moved", async () => {
    const native = group({
      head: vi.fn().mockResolvedValue({ id: "later" }),
      checkpoint: vi.fn().mockResolvedValue({
        checkpoint: { id: "captured" },
        headUpdate: { group: "history", previous: undefined, head: "captured", changed: true, reason: "initialized" },
      }),
    });
    const history = new Snapshot(native as never);
    const captured = await history.checkpointWith(options => options.name("base").recordIntegrity());
    expect(captured.checkpoint.id).toBe("captured");
    expect(captured.headUpdate.head).toBe("captured");
    expect(captured.headUpdate.previous).toBeNull();
    expect(native.head).not.toHaveBeenCalled();
    expect(native.checkpoint).toHaveBeenCalledWith({ name: "base", recordIntegrity: true });
  });

  it("preserves initial-capture identity without rereading the group", () => {
    const native = group();
    const result = snapshotCreateResult({
      snapshot: native,
      checkpoint: { id: "initial" },
      headUpdate: { group: "history", previous: null, head: "initial", reason: "initialized", changed: true },
    } as never);
    expect(result.snapshot.name).toBe("history");
    expect(result.checkpoint.id).toBe("initial");
    expect(native.head).not.toHaveBeenCalled();
  });
});

it("preserves committed import facts and callback options without rereading head", async () => {
  const native = group();
  const added = ["new"];
  const warnings = ["cleanup remains"];
  vi.mocked(napi.SnapshotGroup.load).mockResolvedValue({ operationId: "attempt", snapshot: native, checkpoints: [], added, reused: ["old"], warnings,
    headUpdate: { group: "history", previous: undefined, head: undefined, reason: "ambiguous_candidates", changed: false } } as never);
  const result = await Snapshot.loadWith("history", ["child.msb", "base.msb"], options => options.destDir("store").base("external.msb").setHead());
  expect(napi.SnapshotGroup.load).toHaveBeenCalledWith("history", ["child.msb", "base.msb"], { dest: "store", base: "external.msb", setHead: true });
  added.push("later"); warnings.push("later");
  expect(result.added).toEqual(["new"]);
  expect(result.reused).toEqual(["old"]);
  expect(result.warnings).toEqual(["cleanup remains"]);
  expect(result.operationId).toBe("attempt");
  expect(result.headUpdate.head).toBeNull();
  expect(native.head).not.toHaveBeenCalled();
});
