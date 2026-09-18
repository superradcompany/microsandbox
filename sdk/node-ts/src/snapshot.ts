import { UnsupportedError } from "./errors.js";
import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiSnapshot,
  type NapiSnapshotArchive,
  type NapiSnapshotBuilderSetters,
  type NapiSnapshotCopyBuilder,
  type NapiSnapshotCopyBuilderSetters,
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
export type SnapshotScope = "disk" | "full";

/** Optional guest writeback. Required owned/external-storage barriers are always retained. */
export type GuestFlush = "auto" | "required" | "skip";

/** Canonical closed state family from schema-1 `snapshot.json`. */
export type SnapshotState =
  | {
      readonly kind: "file";
      readonly format: "raw" | "qcow2";
      readonly fstype: string;
      readonly upper: {
        readonly file: string;
        readonly sizeBytes: bigint;
        readonly integrity:
          | {
              readonly algorithm: "sha256" | "msb-sparse-sha256-v1";
              readonly digest: string;
            }
          | {
              readonly algorithm: "msb-file-merkle-blake3-v1";
              /** Compatibility alias for `root`. */
              readonly digest: string;
              readonly root: string;
              readonly logicalSize: bigint;
              readonly leafSize: number;
            }
          | null;
      };
    }
  | {
      readonly kind: "checkpoint";
      readonly checkpointId: string;
      readonly manifest: string;
    };

/**
 * Bundle options for `Snapshot.save` and instance `saveTo` methods.
 */
export interface SaveOpts {
  /** Omit disk layers and RAM objects supplied by this base; mutually exclusive with lastLayers/withParents. */
  since?: string;
  /** Newest N sealed disk layers. Full snapshots still include all memory/device state. */
  lastLayers?: number;
  /** Walk the parent chain and include each ancestor in the archive. */
  withParents?: boolean;
  /** Include the OCI image cache so the archive boots offline. */
  withImage?: boolean;
  /** Skip zstd compression and write a plain `.tar`. */
  plainTar?: boolean;
}

/** Options for importing one or more archives into a snapshot group. */
export interface LoadOpts {
  /** Parent directory containing snapshot groups. */
  dest?: string;
  /** External snapshot or standalone archive for dependencies absent from the batch/group. */
  base?: string;
  /** Destination group; generated when omitted. */
  group?: string;
  /** Select the unique imported tip even when it is not a fast-forward. */
  setHead?: boolean;
}

/** Outcome of reading or selecting a snapshot group's head. */
export interface HeadUpdate {
  readonly group: string;
  readonly previous: string | null;
  readonly head: string;
  readonly reason: string;
  readonly changed: boolean;
}

/** Result of an explicit `Snapshot.verify()` call. */
export type SnapshotVerifyReport =
  | {
      readonly digest: string;
      readonly path: string;
      readonly upper: { readonly kind: "notRecorded" };
      readonly checkpoint?: { readonly kind: "verified"; readonly root: string };
    }
  | {
      readonly digest: string;
      readonly path: string;
      readonly upper: {
        readonly kind: "verified";
        readonly algorithm: string;
        readonly digest: string;
      };
      readonly checkpoint?: { readonly kind: "verified"; readonly root: string };
    };

/**
 * Fluent builder for a snapshot. Returned by `Snapshot.builder(name)`.
 *
 * Mirrors the napi-rs class: every setter mutates in place and returns
 * `this`. The terminal `create()` is wrapped to return a TS `Snapshot`
 * (so we can keep type-level distinction from the raw napi class).
 */
export interface SnapshotBuilder extends NapiSnapshotBuilderSetters {
  guestFlush(policy: GuestFlush): this;
  create(): Promise<Snapshot>;
  createArchive(out: string, plainTar?: boolean): Promise<SnapshotArchive>;
}

/** Result of direct sandbox-to-archive capture. */
export class SnapshotArchive {
  /** @internal */
  constructor(readonly inner: NapiSnapshotArchive) {}

  get id(): string {
    return this.inner.id;
  }

  get descriptorDigest(): string {
    return this.inner.descriptorDigest;
  }

  get path(): string {
    return this.inner.path;
  }
}

/** Builder for copying a snapshot archive with replacement metadata. */
export interface SnapshotCopyBuilder extends NapiSnapshotCopyBuilderSetters {
  save(): Promise<void>;
}

/**
 * A backend-neutral snapshot artifact.
 *
 * Returned by `Snapshot.builder(name).create()`, `Snapshot.open(...)`,
 * and `SandboxHandle.snapshot(name)`.
 *
 * The snapshot retains its originating backend internally and exposes a
 * stable reference for subsequent lifecycle and restore operations.
 */
export class Snapshot {
  /** @internal */
  readonly inner: NapiSnapshot;

  /** @internal */
  constructor(inner: NapiSnapshot) {
    this.inner = inner;
  }

  /**
   * Begin building a snapshot using the active backend; local names may be generated.
   *
   * The source sandbox is required:
   * `Snapshot.builder("clean").fromSandbox("box").create()`.
   *
   * Use `group(name)` to select a group and `destDir(dir)` to select its
   * parent directory. The default group is the source sandbox's name.
   */
  static builder(name = ""): SnapshotBuilder {
    return wrapBuilder(new napi.SnapshotBuilder(name));
  }

  /**
   * Open an existing snapshot. Strings are interpreted by the active backend.
   *
   * Cheap metadata validation only — does not read snapshot contents.
   */
  static async open(pathOrName: string): Promise<Snapshot> {
    const inner = await withMappedErrors(() => napi.Snapshot.open(pathOrName));
    return new Snapshot(inner);
  }

  /** Look up a snapshot using the active backend's public identifier. */
  static async get(nameOrDigest: string): Promise<SnapshotHandle> {
    const raw = await withMappedErrors(() => napi.Snapshot.get(nameOrDigest));
    return new SnapshotHandle(raw);
  }

  /** List snapshots visible through the active backend. */
  static async list(): Promise<SnapshotHandle[]> {
    const infos = await withMappedErrors(() => napi.Snapshot.list());
    return infos.map(snapshotInfoToHandle);
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
   * snapshots directory. Recorded payload integrity is preserved for
   * explicit verification. Compression is detected from magic bytes.
   */
  static async load(archive: string, dest?: string, base?: string): Promise<SnapshotHandle> {
    const raw = await withMappedErrors(() => napi.Snapshot.load(archive, dest, base));
    return new SnapshotHandle(raw);
  }

  /** Import into a selected or generated group, with optional head selection. */
  static async loadWithOptions(archive: string, opts: LoadOpts = {}): Promise<SnapshotHandle> {
    const raw = await withMappedErrors(() => napi.Snapshot.loadWithOptions(archive, opts));
    return new SnapshotHandle(raw);
  }

  /** Import archives together into one group, resolving dependencies regardless of input order. */
  static async loadMany(archives: string[], opts: LoadOpts = {}): Promise<SnapshotHandle[]> {
    const raw = await withMappedErrors(() => napi.Snapshot.loadMany(archives, opts));
    return raw.map((handle) => new SnapshotHandle(handle));
  }

  /** Read a group's head, or select `group:member` as its head. */
  static async groupHead(selector: string): Promise<HeadUpdate> {
    const update = await withMappedErrors(() => napi.Snapshot.groupHead(selector));
    return { ...update, previous: update.previous ?? null };
  }

  //--------------------------------------------------------------------------
  // Instance accessors
  //--------------------------------------------------------------------------

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

  /** Stable value accepted by `Sandbox.restore()`. */
  get reference(): string {
    return this.inner.reference;
  }

  /** How the backend resolves `reference`. */
  get referenceKind(): "id" | "path" {
    return this.inner.referenceKind;
  }

  /** Outcome of the group head update performed by this capture. */
  get headUpdate(): HeadUpdate | null {
    const update = this.inner.headUpdate;
    return update ? { ...update, previous: update.previous ?? null } : null;
  }

  /** Canonical content digest (`sha256:hex`). The snapshot's identity. */
  get id(): string {
    return this.inner.id;
  }

  /** SHA-256 digest of the canonical descriptor. */
  get digest(): string {
    return this.inner.digest;
  }

  /** Backend-reported stored payload size in bytes. */
  get sizeBytes(): bigint | null {
    return this.inner.sizeBytes ?? null;
  }

  /** Closed state projection matching `snapshot.json`. */
  get state(): SnapshotState {
    if (this.inner.stateKind === "checkpoint") {
      return {
        kind: "checkpoint",
        checkpointId: requiredProjectionString(
          this.inner.checkpointId,
          "checkpointId",
        ),
        manifest: requiredProjectionString(
          this.inner.checkpointManifestDigest,
          "checkpointManifestDigest",
        ),
      };
    }
    if (this.inner.stateKind !== "file") {
      throw invalidProjection(`unknown stateKind ${this.inner.stateKind}`);
    }

    const format = requiredProjectionString(this.inner.format, "format");
    if (format !== "raw" && format !== "qcow2") {
      throw invalidProjection(`unknown file-state format ${format}`);
    }
    const sizeBytes = this.inner.sizeBytes;
    if (typeof sizeBytes !== "bigint") {
      throw invalidProjection("missing file-state sizeBytes");
    }
    const algorithm = this.inner.upperIntegrityAlgorithm;
    const value = this.inner.upperIntegrityDigest;
    let projectedIntegrity: Extract<SnapshotState, { kind: "file" }>["upper"]["integrity"];
    if (algorithm == null && value == null) {
      projectedIntegrity = null;
    } else {
      const requiredAlgorithm = requiredProjectionString(
        algorithm,
        "upperIntegrityAlgorithm",
      );
      const requiredValue = requiredProjectionString(
        value,
        "upperIntegrityDigest",
      );
      if (requiredAlgorithm === "msb-file-merkle-blake3-v1") {
        const logicalSize = this.inner.upperIntegrityLogicalSize;
        const leafSize = this.inner.upperIntegrityLeafSize;
        if (typeof logicalSize !== "bigint") {
          throw invalidProjection("missing upperIntegrityLogicalSize");
        }
        if (typeof leafSize !== "number") {
          throw invalidProjection("missing upperIntegrityLeafSize");
        }
        projectedIntegrity = {
          algorithm: requiredAlgorithm,
          digest: requiredValue,
          root: requiredValue,
          logicalSize,
          leafSize,
        };
      } else if (
        requiredAlgorithm === "sha256" ||
        requiredAlgorithm === "msb-sparse-sha256-v1"
      ) {
        projectedIntegrity = {
          algorithm: requiredAlgorithm,
          digest: requiredValue,
        };
      } else {
        throw invalidProjection(
          `unknown upper integrity algorithm ${requiredAlgorithm}`,
        );
      }
    }

    return {
      kind: "file",
      format,
      fstype: requiredProjectionString(this.inner.fstype, "fstype"),
      upper: {
        file: requiredProjectionString(this.inner.upperFile, "upperFile"),
        sizeBytes,
        integrity: projectedIntegrity,
      },
    };
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
  get format(): "raw" | "qcow2" | null {
    return (this.inner.format as "raw" | "qcow2" | undefined) ?? null;
  }

  /** Filesystem type inside the upper (e.g. `"ext4"`). */
  get fstype(): string | null {
    return this.inner.fstype ?? null;
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
   * Parse snapshot artifacts found directly beneath a backend-visible directory.
   * Throws `UnsupportedError` when the backend does not expose artifact files.
   */
  static async listDir(dir: string): Promise<Snapshot[]> {
    const raw = await withMappedErrors(() => napi.Snapshot.listDir(dir));
    return raw.map((snapshot) => new Snapshot(snapshot));
  }

  /**
   * Bundle this snapshot into a `.tar.zst` archive.
   * Throws `UnsupportedError` when the backend does not expose artifact archives.
   */
  async saveTo(out: string, opts?: SaveOpts): Promise<void> {
    await withMappedErrors(() => this.inner.saveTo(out, opts));
  }

  /**
   * Configure a new archive containing this snapshot's disk data and
   * replacement labels and integrity metadata.
   * Throws `UnsupportedError` when the backend does not expose artifact archives.
   */
  copyTo(outputArchivePath: string): SnapshotCopyBuilder {
    return wrapCopyBuilder(this.inner.copyTo(outputArchivePath));
  }

  /**
   * Verify this snapshot's recorded payload integrity.
   * Throws `UnsupportedError` when the backend does not expose payload verification.
   */
  async verify(): Promise<SnapshotVerifyReport> {
    const report = await withMappedErrors(() => this.inner.verify());
    return verifyReportToTs(report);
  }
}

/** @internal */
function wrapBuilder(nb: InstanceType<typeof napi.SnapshotBuilder>): SnapshotBuilder {
  const origCreate = nb.create.bind(nb);
  const origCreateArchive = nb.createArchive.bind(nb);
  (nb as unknown as { create: () => Promise<Snapshot> }).create = async () => {
    const inner = await withMappedErrors(() => origCreate());
    return new Snapshot(inner);
  };
  (
    nb as unknown as {
      createArchive: (out: string, plainTar?: boolean) => Promise<SnapshotArchive>;
    }
  ).createArchive = async (out: string, plainTar?: boolean) => {
    const inner = await withMappedErrors(() => origCreateArchive(out, plainTar));
    return new SnapshotArchive(inner);
  };
  return nb as unknown as SnapshotBuilder;
}

/** @internal */
function wrapCopyBuilder(builder: NapiSnapshotCopyBuilder): SnapshotCopyBuilder {
  const originalSave = builder.save.bind(builder);
  builder.save = () => withMappedErrors(originalSave);
  return builder;
}

/** @internal */
function verifyReportToTs(r: NapiSnapshotVerifyReport): SnapshotVerifyReport {
  const checkpoint =
    typeof r.checkpointRoot === "string"
      ? { kind: "verified" as const, root: r.checkpointRoot }
      : undefined;
  if (r.upperKind === "notRecorded") {
    return {
      digest: r.digest,
      path: r.path,
      upper: { kind: "notRecorded" },
      ...(checkpoint === undefined ? {} : { checkpoint }),
    };
  }
  if (r.upperKind === "verified") {
    return {
      digest: r.digest,
      path: r.path,
      upper: {
        kind: "verified",
        algorithm: requiredProjectionString(
          r.upperAlgorithm,
          "verify.upperAlgorithm",
        ),
        digest: requiredProjectionString(r.upperDigest, "verify.upperDigest"),
      },
      ...(checkpoint === undefined ? {} : { checkpoint }),
    };
  }
  throw invalidProjection(`unknown verification kind ${r.upperKind}`);
}

/** @internal */
function requiredProjectionString(
  value: string | null | undefined,
  field: string,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw invalidProjection(`missing ${field}`);
  }
  return value;
}

/** @internal */
function invalidProjection(detail: string): Error {
  return new Error(`invalid native snapshot projection: ${detail}`);
}

/** @internal */
export function _napiSnapshotInfoIsHandle(
  info: NapiSnapshotInfo,
): info is NapiSnapshotInfo {
  return typeof info?.digest === "string";
}
