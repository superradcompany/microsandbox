import { describe, expect, it, vi } from "vitest";
import { Snapshot } from "../../dist/snapshot.js";
import { napi } from "../../dist/internal/napi.js";

vi.mock("../../dist/internal/napi.js", () => ({
  napi: { Snapshot: { loadWithOptions: vi.fn(), loadMany: vi.fn(), groupHead: vi.fn() } },
}));
import { SnapshotHandle } from "../../dist/snapshot-handle.js";

function projectedSnapshot(
  overrides: Record<string, unknown> = {},
): Snapshot {
  const inner = {
    reference: "/snapshots/example",
    referenceKind: "path",
    digest: `sha256:${"a".repeat(64)}`,
    sizeBytes: 4096n,
    imageRef: "docker.io/library/alpine:3.20",
    imageManifestDigest: `sha256:${"b".repeat(64)}`,
    stateKind: "file",
    format: "raw",
    fstype: "ext4",
    upperFile: "upper.ext4",
    upperIntegrityAlgorithm: "msb-sparse-sha256-v1",
    upperIntegrityDigest: `sha256:${"c".repeat(64)}`,
    upperIntegrityLogicalSize: null,
    upperIntegrityLeafSize: null,
    checkpointId: null,
    checkpointManifestDigest: null,
    parent: null,
    scope: "disk",
    createdAt: "2026-07-24T00:00:00Z",
    labels: {},
    sourceSandbox: null,
    verify: async () => ({
      digest: `sha256:${"a".repeat(64)}`,
      path: "/snapshots/example",
      upperKind: "verified",
      upperAlgorithm: "msb-sparse-sha256-v1",
      upperDigest: `sha256:${"c".repeat(64)}`,
      checkpointRoot: null,
    }),
    ...overrides,
  };
  return new Snapshot(inner as never);
}

describe("Snapshot native projections", () => {
  it("exposes the create outcome with a nullable previous head", () => {
    const snapshot = projectedSnapshot({
      headUpdate: {
        group: "work", previous: undefined, head: "snapshot-1", reason: "initialized", changed: true,
      },
    });
    expect(snapshot.headUpdate).toEqual({
      group: "work", previous: null, head: "snapshot-1", reason: "initialized", changed: true,
    });
    expect(projectedSnapshot().headUpdate).toBeNull();
  });

  it("forwards import options and preserves a retained-head outcome", async () => {
    const headUpdate = {
      group: "work", previous: "snapshot-1", head: "snapshot-1", reason: "diverged", changed: false,
    };
    vi.mocked(napi.Snapshot.loadWithOptions).mockResolvedValue({
      id: "snapshot-2", digest: "sha256:two", group: "work", headUpdate,
      name: "other", createdAt: 0, path: "/snapshots/work/snapshot-2",
    } as never);
    const options = { dest: "/snapshots", base: "work:base", group: "work", setHead: false };
    const handle = await Snapshot.loadWithOptions("other.msb", options);
    expect(napi.Snapshot.loadWithOptions).toHaveBeenCalledWith("other.msb", options);
    expect(handle.group).toBe("work");
    expect(handle.id).toBe("snapshot-2");
    expect(handle.headUpdate).toEqual(headUpdate);
  });

  it("forwards a member selector for explicit head selection", async () => {
    vi.mocked(napi.Snapshot.groupHead).mockResolvedValue({
      group: "work", previous: "snapshot-2", head: "snapshot-1", reason: "selected", changed: true,
    });
    expect(await Snapshot.groupHead("work:baseline")).toMatchObject({ reason: "selected", changed: true });
    expect(napi.Snapshot.groupHead).toHaveBeenCalledWith("work:baseline");
  });

  it("loads a batch once and preserves input-order handles and headless outcomes", async () => {
    vi.mocked(napi.Snapshot.loadMany).mockResolvedValue([
      { id: "snapshot-tip", digest: "sha256:tip", path: "/snapshots/received/tip", group: "received", createdAt: 0 },
      { id: "snapshot-base", digest: "sha256:base", path: "/snapshots/received/base", group: "received", createdAt: 0 },
    ] as never);
    const archives = ["changes.msb", "base.msb"];
    const options = { group: "received", dest: "/snapshots" };
    const handles = await Snapshot.loadMany(archives, options);
    expect(napi.Snapshot.loadMany).toHaveBeenCalledWith(archives, options);
    expect(handles.map((handle) => handle.id)).toEqual(["snapshot-tip", "snapshot-base"]);
    expect(handles.map((handle) => handle.group)).toEqual(["received", "received"]);
    expect(handles.every((handle) => handle.headUpdate === null)).toBe(true);
  });

  it("passes explicit batch head selection to the native importer", async () => {
    vi.mocked(napi.Snapshot.loadMany).mockResolvedValue([]);
    await Snapshot.loadMany(["tip.msb", "base.msb"], { group: "received", base: "outside:base", setHead: true });
    expect(napi.Snapshot.loadMany).toHaveBeenLastCalledWith(
      ["tip.msb", "base.msb"], { group: "received", base: "outside:base", setHead: true },
    );
  });

  it("preserves backend-neutral references on snapshots and handles", () => {
    const snapshot = projectedSnapshot();
    expect(snapshot.reference).toBe("/snapshots/example");
    expect(snapshot.referenceKind).toBe("path");

    const handle = new SnapshotHandle({
      reference: "snapshot-id",
      referenceKind: "id",
      digest: `sha256:${"a".repeat(64)}`,
      name: "example",
      parentDigest: null,
      scope: "disk",
      imageRef: "docker.io/library/alpine:3.20",
      stateKind: "file",
      format: "raw",
      fstype: "ext4",
      checkpointManifestDigest: null,
      sizeBytes: 4096n,
      locality: "provider_linked",
      availability: "ready",
      migrationState: "complete",
      migrationErrorCode: null,
      createdAt: 0,
    } as never);
    expect(handle.reference).toBe("snapshot-id");
    expect(handle.referenceKind).toBe("id");
  });

  it("returns complete file and checkpoint states", () => {
    expect(projectedSnapshot().state).toMatchObject({
      kind: "file",
      format: "raw",
      fstype: "ext4",
      upper: { file: "upper.ext4", sizeBytes: 4096n },
    });

    const checkpoint = projectedSnapshot({
      stateKind: "checkpoint",
      sizeBytes: null,
      format: null,
      fstype: null,
      upperFile: null,
      upperIntegrityAlgorithm: null,
      upperIntegrityDigest: null,
      upperIntegrityLogicalSize: null,
      upperIntegrityLeafSize: null,
      checkpointId: "checkpoint-1",
      checkpointManifestDigest: `sha256:${"d".repeat(64)}`,
    });
    expect(checkpoint.state).toEqual({
      kind: "checkpoint",
      checkpointId: "checkpoint-1",
      manifest: `sha256:${"d".repeat(64)}`,
    });
  });

  it("rejects incomplete or unknown state projections", () => {
    expect(() => projectedSnapshot({ sizeBytes: null }).state).toThrow(
      "missing file-state sizeBytes",
    );
    expect(
      () =>
        projectedSnapshot({
          stateKind: "checkpoint",
          checkpointId: null,
          checkpointManifestDigest: `sha256:${"d".repeat(64)}`,
        }).state,
    ).toThrow("missing checkpointId");
    expect(() => projectedSnapshot({ stateKind: "future" }).state).toThrow(
      "unknown stateKind future",
    );
  });

  it("preserves all Merkle descriptor parameters", () => {
    const root = `blake3:${"d".repeat(64)}`;
    const snapshot = projectedSnapshot({
      upperIntegrityAlgorithm: "msb-file-merkle-blake3-v1",
      upperIntegrityDigest: root,
      upperIntegrityLogicalSize: 4096n,
      upperIntegrityLeafSize: 65536,
    });

    expect(snapshot.state).toMatchObject({
      kind: "file",
      upper: {
        integrity: {
          algorithm: "msb-file-merkle-blake3-v1",
          digest: root,
          root,
          logicalSize: 4096n,
          leafSize: 65536,
        },
      },
    });
  });

  it("rejects malformed verification reports", async () => {
    const missingAlgorithm = projectedSnapshot({
      verify: async () => ({
        digest: `sha256:${"a".repeat(64)}`,
        path: "/snapshots/example",
        upperKind: "verified",
        upperAlgorithm: null,
        upperDigest: `sha256:${"c".repeat(64)}`,
      }),
    });
    await expect(missingAlgorithm.verify()).rejects.toThrow(
      "missing verify.upperAlgorithm",
    );

    const unknownKind = projectedSnapshot({
      verify: async () => ({
        digest: `sha256:${"a".repeat(64)}`,
        path: "/snapshots/example",
        upperKind: "skipped",
        upperAlgorithm: null,
        upperDigest: null,
      }),
    });
    await expect(unknownKind.verify()).rejects.toThrow(
      "unknown verification kind skipped",
    );
  });

  it("projects snapshots without recorded integrity", async () => {
    const snapshot = projectedSnapshot({
      upperIntegrityAlgorithm: null,
      upperIntegrityDigest: null,
      upperIntegrityLogicalSize: null,
      upperIntegrityLeafSize: null,
      verify: async () => ({
        digest: `sha256:${"a".repeat(64)}`,
        path: "/snapshots/example",
        upperKind: "notRecorded",
        upperAlgorithm: null,
        upperDigest: null,
      }),
    });

    expect(snapshot.state).toMatchObject({
      kind: "file",
      upper: { integrity: null },
    });
    await expect(snapshot.verify()).resolves.toMatchObject({
      upper: { kind: "notRecorded" },
    });
  });

  it("projects verified checkpoint closures without overloading upper integrity", async () => {
    const root = `sha256:${"d".repeat(64)}`;
    const snapshot = projectedSnapshot({
      verify: async () => ({
        digest: `sha256:${"a".repeat(64)}`,
        path: "/snapshots/example",
        upperKind: "notRecorded",
        upperAlgorithm: null,
        upperDigest: null,
        checkpointRoot: root,
      }),
    });

    await expect(snapshot.verify()).resolves.toEqual({
      digest: `sha256:${"a".repeat(64)}`,
      path: "/snapshots/example",
      upper: { kind: "notRecorded" },
      checkpoint: { kind: "verified", root },
    });
  });
  it("delegates saveTo to live snapshots and handles", async () => {
    const saveSnapshot = vi.fn().mockResolvedValue(undefined);
    const snapshot = projectedSnapshot({ saveTo: saveSnapshot });
    await snapshot.saveTo("/tmp/snapshot.tar.zst", { withImage: true });
    expect(saveSnapshot).toHaveBeenCalledWith("/tmp/snapshot.tar.zst", {
      withImage: true,
    });

    const saveHandle = vi.fn().mockResolvedValue(undefined);
    const handle = new SnapshotHandle({
      reference: "snapshot-id",
      referenceKind: "id",
      digest: `sha256:${"a".repeat(64)}`,
      name: "example",
      parentDigest: null,
      scope: "disk",
      imageRef: "docker.io/library/alpine:3.20",
      stateKind: "file",
      format: "raw",
      fstype: "ext4",
      checkpointManifestDigest: null,
      sizeBytes: 4096n,
      locality: "provider_linked",
      availability: "ready",
      migrationState: "complete",
      migrationErrorCode: null,
      createdAt: 0,
      saveTo: saveHandle,
    } as never);
    await handle.saveTo("/tmp/handle.tar", { plainTar: true });
    expect(saveHandle).toHaveBeenCalledWith("/tmp/handle.tar", {
      plainTar: true,
    });
  });

  it("builds a snapshot archive copy with replacement metadata", async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    const labels = vi.fn().mockReturnThis();
    const recordIntegrity = vi.fn().mockReturnThis();
    const copyTo = vi.fn().mockReturnValue({ labels, recordIntegrity, save });
    const snapshot = projectedSnapshot({ copyTo });

    await snapshot
      .copyTo("/tmp/copied.tar.zst")
      .labels({ environment: "test" })
      .recordIntegrity(true)
      .save();

    expect(copyTo).toHaveBeenCalledWith("/tmp/copied.tar.zst");
    expect(labels).toHaveBeenCalledWith({ environment: "test" });
    expect(recordIntegrity).toHaveBeenCalledWith(true);
    expect(save).toHaveBeenCalledOnce();
  });
});

describe("legacy snapshot paths", () => {
  it.each(["id", "path"])("rejects remote %s references", (referenceKind) => {
    expect(() => projectedSnapshot({ referenceKind }).path).toThrow("no local filesystem path");
    const handle = new SnapshotHandle({ reference: "/remote/snapshot", referenceKind, createdAt: 0 } as never);
    expect(() => handle.path).toThrow("no local filesystem path");
  });
  it("preserves local paths on snapshots and listed handles", () => {
    expect(projectedSnapshot({ path: "/local/snapshot" }).path).toBe("/local/snapshot");
    const handle = new SnapshotHandle({ path: "/local/snapshot", reference: "/local/snapshot", referenceKind: "path", createdAt: 0 } as never);
    expect(handle.path).toBe("/local/snapshot");
  });
});
