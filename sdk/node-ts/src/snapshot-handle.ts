import { withMappedErrors } from "./internal/error-mapping.js";
import type {
  NapiSnapshotHandle,
  NapiSnapshotInfo,
} from "./internal/napi.js";
import { Snapshot } from "./snapshot.js";

const READ_ONLY_MSG =
  "SnapshotHandle is read-only — fetch a live handle via Snapshot.get(name) for lifecycle methods.";

/**
 * Lightweight handle backed by an index row.
 *
 * Returned by `Snapshot.list()` and `Snapshot.get(...)`. Values are
 * snapshotted from the index at construction time — call
 * `Snapshot.get(...)` again for a fresh reading if needed.
 */
export class SnapshotHandle {
  private readonly inner: NapiSnapshotHandle | NapiSnapshotInfo;
  /** Manifest digest (`sha256:hex`) — canonical identity. */
  readonly digest: string;
  /** Convenience name. `null` for digest-only entries. */
  readonly name: string | null;
  /** Manifest digest of the parent snapshot, or `null` for a root. */
  readonly parentDigest: string | null;
  /** Image reference the snapshot was taken from. */
  readonly imageRef: string;
  /** On-disk format of the upper layer. */
  readonly format: "raw" | "qcow2";
  /** Apparent size of the upper file at index time. */
  readonly sizeBytes: bigint | null;
  /** Snapshot creation time (from manifest). */
  readonly createdAt: Date;
  /** Local artifact directory path. */
  readonly path: string;

  /** @internal */
  constructor(inner: NapiSnapshotHandle | NapiSnapshotInfo) {
    this.inner = inner;
    this.digest = inner.digest;
    this.name = (inner.name ?? null) as string | null;
    this.parentDigest = (inner.parentDigest ?? null) as string | null;
    this.imageRef = inner.imageRef;
    this.format = inner.format as "raw" | "qcow2";
    this.sizeBytes = sizeBytesToBigInt(inner.sizeBytes);
    this.createdAt = new Date(inner.createdAt);
    this.path = inner.path;
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
