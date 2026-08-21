import { describe, expect, it, vi } from "vitest";
import { Snapshot } from "../../dist/snapshot.js";
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
    }),
    ...overrides,
  };
  return new Snapshot(inner as never);
}

describe("Snapshot native projections", () => {
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
});
