import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiSnapshot,
  type NapiSnapshotBuilderSetters,
  type NapiSnapshotInfo,
  type NapiSnapshotVerifyReport,
} from "./internal/napi.js";
import {
  SnapshotHandle,
  snapshotInfoToHandle,
} from "./snapshot-handle.js";

/**
 * Snapshot payload scope.
 */
export type SnapshotScope = "disk" | "resumable";

/**
 * Bundle options for `Snapshot.save`.
 */
export interface SaveOpts {
  /** Walk the parent chain and include each ancestor in the archive. */
  withParents?: boolean;
  /** Include the OCI image cache so the archive boots offline. */
  withImage?: boolean;
  /** Skip zstd compression and write a plain `.tar`. */
  plainTar?: boolean;
}

/**
 * Result of `Snapshot.verify()`. The `upper` discriminant is
 * `"notRecorded"` when no integrity hash was stored at create time,
 * or `"verified"` when the recorded hash matched the recomputed one.
 */
export type SnapshotVerifyReport =
  | {
      readonly digest: string;
      readonly path: string;
      readonly upper: { readonly kind: "notRecorded" };
    }
  | {
      readonly digest: string;
      readonly path: string;
      readonly upper: {
        readonly kind: "verified";
        readonly algorithm: string;
        readonly digest: string;
      };
    };

/**
 * Fluent builder for a snapshot. Returned by `Snapshot.builder(name)`.
 *
 * Mirrors the napi-rs class: every setter mutates in place and returns
 * `this`. The terminal `create()` is wrapped to return a TS `Snapshot`
 * (so we can keep type-level distinction from the raw napi class).
 */
export interface SnapshotBuilder extends NapiSnapshotBuilderSetters {
  create(): Promise<Snapshot>;
}

/**
 * A snapshot artifact on disk.
 *
 * Returned by `Snapshot.builder(name).create()`, `Snapshot.open(...)`,
 * and `SandboxHandle.snapshot(name)`.
 *
 * The artifact is a directory containing `snapshot.json` and the
 * captured `upper.ext4`. The directory is the source of truth; the
 * local DB index (used for queries like `Snapshot.list()`) is just a
 * cache and is rebuildable via `Snapshot.reindex()`.
 */
export class Snapshot {
  /** @internal */
  readonly inner: NapiSnapshot;

  /** @internal */
  constructor(inner: NapiSnapshot) {
    this.inner = inner;
  }

  /**
   * Begin building a snapshot named `name`, stored under the default
   * snapshots directory.
   *
   * The source sandbox is required:
   * `Snapshot.builder("clean").fromSandbox("box").create()`.
   *
   * Use `destDir(dir)` to create the artifact under a different parent
   * directory instead; it lands at `destDir/<name>`, and the name stays
   * the snapshot's identity either way.
   */
  static builder(name: string): SnapshotBuilder {
    return wrapBuilder(new napi.SnapshotBuilder(name));
  }

  /**
   * Open an existing snapshot artifact. Bare names resolve under the
   * default snapshots directory; anything else is treated as a path.
   *
   * Cheap metadata validation only — does not read the upper file.
   * Use `verify()` for content checks.
   */
  static async open(pathOrName: string): Promise<Snapshot> {
    const inner = await withMappedErrors(() => napi.Snapshot.open(pathOrName));
    return new Snapshot(inner);
  }

  /** Look up an indexed snapshot by digest, name, or path. */
  static async get(nameOrDigest: string): Promise<SnapshotHandle> {
    const raw = await withMappedErrors(() => napi.Snapshot.get(nameOrDigest));
    return new SnapshotHandle(raw);
  }

  /** List indexed snapshots from the local DB cache. */
  static async list(): Promise<SnapshotHandle[]> {
    const infos = await withMappedErrors(() => napi.Snapshot.list());
    return infos.map(snapshotInfoToHandle);
  }

  /**
   * Walk a directory and parse each subdirectory's manifest. Does
   * not touch the index — useful for inspecting external snapshot
   * collections that were never imported. Skips entries that don't
   * look like snapshot artifacts.
   */
  static async listDir(dir: string): Promise<Snapshot[]> {
    const raw = await withMappedErrors(() => napi.Snapshot.listDir(dir));
    return raw.map((s) => new Snapshot(s));
  }

  /**
   * Remove a snapshot by path, name, or digest. Refuses if the
   * snapshot has indexed children unless `force` is set.
   */
  static async remove(
    pathOrName: string,
    opts?: { force?: boolean },
  ): Promise<void> {
    await withMappedErrors(() =>
      napi.Snapshot.remove(pathOrName, { force: opts?.force ?? false }),
    );
  }

  /**
   * Walk the snapshots directory (default: configured snapshots dir)
   * and rebuild the local index. Returns the number of artifacts
   * indexed.
   */
  static async reindex(dir?: string): Promise<number> {
    return withMappedErrors(() => napi.Snapshot.reindex(dir));
  }

  /**
   * Bundle a snapshot into a `.tar.zst` archive. The recorded
   * manifest is archived as-is, so create the snapshot with
   * `recordIntegrity()` if receivers must verify content.
   */
  static async save(
    nameOrPath: string,
    out: string,
    opts?: SaveOpts,
  ): Promise<void> {
    await withMappedErrors(() => napi.Snapshot.save(nameOrPath, out, opts));
  }

  /**
   * Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
   * snapshots directory, verifying recorded integrity on the way in.
   * Compression is detected from magic bytes.
   */
  static async load(archive: string, dest?: string): Promise<SnapshotHandle> {
    const raw = await withMappedErrors(() => napi.Snapshot.load(archive, dest));
    return new SnapshotHandle(raw);
  }

  //--------------------------------------------------------------------------
  // Instance accessors
  //--------------------------------------------------------------------------

  /** Path to the artifact directory. */
  get path(): string {
    return this.inner.path;
  }

  /** Canonical content digest (`sha256:hex`). The snapshot's identity. */
  get digest(): string {
    return this.inner.digest;
  }

  /** Apparent size of the captured upper layer in bytes (sparse on disk). */
  get sizeBytes(): bigint {
    return this.inner.sizeBytes;
  }

  /** Image reference the snapshot was taken from. */
  get imageRef(): string {
    return this.inner.imageRef;
  }

  /** OCI manifest digest of the pinned image. */
  get imageManifestDigest(): string {
    return this.inner.imageManifestDigest;
  }

  /** On-disk format of the upper layer. */
  get format(): "raw" | "qcow2" {
    return this.inner.format as "raw" | "qcow2";
  }

  /** Filesystem type inside the upper (e.g. `"ext4"`). */
  get fstype(): string {
    return this.inner.fstype;
  }

  /** Manifest digest of the parent snapshot, or `null` for a root. */
  get parent(): string | null {
    return this.inner.parent ?? null;
  }

  /** Snapshot payload scope. */
  get scope(): SnapshotScope {
    return this.inner.scope as SnapshotScope;
  }

  /** RFC 3339 timestamp when the snapshot was created. */
  get createdAt(): string {
    return this.inner.createdAt;
  }

  /** User-supplied labels (sorted by key in canonical form). */
  get labels(): ReadonlyArray<readonly [string, string]> {
    return Object.entries(this.inner.labels);
  }

  /** Best-effort source-sandbox name, if recorded. */
  get sourceSandbox(): string | null {
    return this.inner.sourceSandbox ?? null;
  }

  /**
   * Recompute the upper layer's content hash and compare against the
   * manifest. Walks data extents only, so a 4 GiB sparse file with a
   * few MB of data verifies in milliseconds.
   *
   * Returns `{ upper: { kind: "notRecorded" } }` when the manifest
   * has no integrity hash recorded.
   */
  async verify(): Promise<SnapshotVerifyReport> {
    const r = await withMappedErrors(() => this.inner.verify());
    return verifyReportToTs(r);
  }
}

/** @internal */
function wrapBuilder(nb: InstanceType<typeof napi.SnapshotBuilder>): SnapshotBuilder {
  const origCreate = nb.create.bind(nb);
  (nb as unknown as { create: () => Promise<Snapshot> }).create = async () => {
    const inner = await withMappedErrors(() => origCreate());
    return new Snapshot(inner);
  };
  return nb as unknown as SnapshotBuilder;
}

/** @internal */
function verifyReportToTs(r: NapiSnapshotVerifyReport): SnapshotVerifyReport {
  if (r.upperKind === "verified") {
    return {
      digest: r.digest,
      path: r.path,
      upper: {
        kind: "verified",
        algorithm: r.upperAlgorithm ?? "",
        digest: r.upperDigest ?? "",
      },
    };
  }
  return {
    digest: r.digest,
    path: r.path,
    upper: { kind: "notRecorded" },
  };
}

/** @internal */
export function _napiSnapshotInfoIsHandle(
  info: NapiSnapshotInfo,
): info is NapiSnapshotInfo {
  return typeof info?.digest === "string";
}
