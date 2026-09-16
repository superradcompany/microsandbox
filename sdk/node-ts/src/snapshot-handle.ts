import { UnsupportedError } from "./errors.js";
import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import type {
  NapiSnapshotHandle,
  NapiSnapshotInfo,
} from "./internal/napi.js";
import { Snapshot, type HeadUpdate, type SaveOpts, type SnapshotScope } from "./snapshot.js";

const READ_ONLY_MSG =
  "SnapshotHandle is read-only — fetch a live handle via Snapshot.get(name) for lifecycle methods.";

/**
 * Lightweight handle returned by the active snapshot backend.
 *
 * Returned by `Snapshot.list()` and `Snapshot.get(...)`. Values are
 * snapshotted at construction time — call
 * `Snapshot.get(...)` again for a fresh reading if needed.
 */
export class SnapshotHandle {
  private readonly inner: NapiSnapshotHandle | NapiSnapshotInfo;
  /** Stable opaque snapshot identity. */
  readonly id: string;
  /** Manifest digest (`sha256:hex`) — canonical identity. */
  readonly digest: string;
  /** Convenience name. `null` for digest-only entries. */
  readonly name: string | null;
  /** Local group containing this indexed snapshot. */
  readonly group: string | null;
  /** Outcome of the group head update performed by this import. */
  readonly headUpdate: HeadUpdate | null;
  /** Manifest digest of the parent snapshot, or `null` for a root. */
  readonly parentDigest: string | null;
  /** Snapshot payload scope. */
  readonly scope: SnapshotScope;
  /** Image reference the snapshot was taken from. */
  readonly imageRef: string;
  /** Closed descriptor state discriminant. */
  readonly stateKind: "file" | "checkpoint";
  /** On-disk format for file state. */
  readonly format: "raw" | "qcow2" | null;
  /** Filesystem type for file state. */
  readonly fstype: string | null;
  /** Checkpoint manifest digest for checkpoint state. */
  readonly checkpointManifestDigest: string | null;
  /** Backend-reported stored payload size, when known. */
  readonly sizeBytes: bigint | null;
  /** Embedded versus provider-linked payload placement. */
  readonly locality: string;
  /** Current local availability. */
  readonly availability: string;
  /** Adjacent-release artifact migration status. */
  readonly migrationState: string;
  /** Stable migration failure code, when blocked. */
  readonly migrationErrorCode: string | null;
  /** Snapshot creation time (from manifest). */
  readonly createdAt: Date;
  /** Stable value accepted by `Sandbox.restore()`. */
  readonly reference: string;
  /** How the backend resolves `reference`. */
  readonly referenceKind: "id" | "path";

  /** @internal */
  constructor(inner: NapiSnapshotHandle | NapiSnapshotInfo) {
    this.inner = inner;
    this.id = inner.id;
    this.digest = inner.digest;
    this.name = (inner.name ?? null) as string | null;
    this.group = inner.group ?? null;
    this.headUpdate = inner.headUpdate
      ? { ...inner.headUpdate, previous: inner.headUpdate.previous ?? null }
      : null;
    this.parentDigest = (inner.parentDigest ?? null) as string | null;
    this.scope = inner.scope as SnapshotScope;
    this.imageRef = inner.imageRef;
    this.stateKind = inner.stateKind as "file" | "checkpoint";
    this.format = (inner.format as "raw" | "qcow2" | undefined) ?? null;
    this.fstype = inner.fstype ?? null;
    this.checkpointManifestDigest = inner.checkpointManifestDigest ?? null;
    this.sizeBytes = sizeBytesToBigInt(inner.sizeBytes);
    this.locality = inner.locality;
    this.availability = inner.availability;
    this.migrationState = inner.migrationState;
    this.migrationErrorCode = inner.migrationErrorCode ?? null;
    this.createdAt = new Date(inner.createdAt);
    this.reference = inner.reference;
    this.referenceKind = inner.referenceKind;
  }

  /** @deprecated Use `reference`. Throws UnsupportedError for remote snapshots. */
  get path(): string {
    try {
      const path = this.inner.path;
      if (path == null) {
        throw new UnsupportedError(
          "Snapshot has no local filesystem path; use reference instead.",
        );
      }
      return path;
    } catch (error) {
      throw mapNapiError(error);
    }
  }

  /** Open and metadata-validate the underlying artifact. */
  async open(): Promise<Snapshot> {
    if (typeof (this.inner as NapiSnapshotHandle).open !== "function") {
      throw new Error(READ_ONLY_MSG);
    }
    const raw = await withMappedErrors(() =>
      (this.inner as NapiSnapshotHandle).open(),
    );
    return new Snapshot(raw);
  }

  /**
   * Remove the artifact and its index row. Refuses if the snapshot
   * has indexed children unless `force` is set.
   */
  async remove(opts?: { force?: boolean }): Promise<void> {
    if (typeof (this.inner as NapiSnapshotHandle).remove !== "function") {
      throw new Error(READ_ONLY_MSG);
    }
    await withMappedErrors(() =>
      (this.inner as NapiSnapshotHandle).remove({ force: opts?.force ?? false }),
    );
  }

  /**
   * Bundle this snapshot into a `.tar.zst` archive.
   * Throws `UnsupportedError` when the backend does not expose artifact archives.
   */
  async saveTo(out: string, opts?: SaveOpts): Promise<void> {
    if (typeof (this.inner as NapiSnapshotHandle).saveTo !== "function") {
      throw new Error(READ_ONLY_MSG);
    }
    await withMappedErrors(() =>
      (this.inner as NapiSnapshotHandle).saveTo(out, opts),
    );
  }
}

function sizeBytesToBigInt(
  v: bigint | number | null | undefined,
): bigint | null {
  if (v === null || v === undefined) return null;
  return typeof v === "bigint" ? v : BigInt(v);
}

/** @internal */
export function snapshotInfoToHandle(info: NapiSnapshotInfo): SnapshotHandle {
  return new SnapshotHandle(info);
}
