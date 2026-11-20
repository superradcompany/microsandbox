import { parseCheckpointRemoval, type CheckpointRemoveResult } from "./snapshot-removal.js";
import { Sandbox, CreationProgressCreate, type RestoreBuilder } from "./sandbox.js";
import type { NapiRestoreBuilder } from "./internal/napi.js";
import { Context, LocalContext, RemoteContext, Checkpoints } from "./context.js";
import { UnsupportedError } from "./errors.js";
import { storageUsageFromHandle, type StorageItemUsage } from "./storage.js";
import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiSnapshot,
  type NapiSnapshotArchive,
  type NapiSnapshotBuilderSetters,
  type NapiSnapshotCopyBuilder,
  type NapiSnapshotCopyBuilderSetters,
  type NapiSnapshotVerifyReport,
} from "./internal/napi.js";

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
  /** Explicit recipient; unsupported required capabilities are refused, never removed. */
  compatibility?: "current" | "0.7.8";
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

/** Archive controls for the receiver-based saveWith callback. */
export class SnapshotSaveOptions {
  private options: SaveOpts = {};
  compatibility(target: "current" | "0.7.8"): this { this.options.compatibility = target; return this; }
  withParents(): this { this.options.withParents = true; return this; }
  withImage(): this { this.options.withImage = true; return this; }
  plainTar(): this { this.options.plainTar = true; return this; }
  since(base: string): this { this.options.since = base; return this; }
  lastLayers(count: number): this { this.options.lastLayers = count; return this; }
  /** @internal */
  toNative(): SaveOpts { return { ...this.options }; }
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
  maximumDiskBytes?: number;
}

/** Outcome of reading or selecting a snapshot group's head. */
export interface HeadUpdate {
  readonly group: string;
  readonly previous: string | null;
  readonly head: string | null;
  readonly reason: string;
  readonly changed: boolean;
}

/** Whole-artifact coverage; older native libraries cannot attest to this field. */
export type SnapshotVerifyCoverage =
  | { readonly kind: "complete" }
  | { readonly kind: "incomplete"; readonly unrecorded: readonly string[] }
  | { readonly kind: "unknown" };

/** Result of an explicit `Checkpoint.verify()` call. Corruption rejects the call. */
export type SnapshotVerifyReport = { readonly coverage: SnapshotVerifyCoverage } & (
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
    }
);

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

/** Exact-member removal options; force never bypasses active readers. */
export class CheckpointRemoveOptions {
  private forced = false;
  force(): this { this.forced = true; return this; }
  /** @internal */
  toNative(): boolean { return this.forced; }
}

/**
 * A backend-neutral snapshot artifact.
 *
 * Returned by `Snapshot.builder(name).create()`, `Snapshot.open(...)`,
 * and `Sandbox.snapshot(name)`.
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

  /** Remove this exact checkpoint and return this operation's head decision. */
  async remove(): Promise<CheckpointRemoveResult> {
    return this.removeWith((options) => options);
  }

  async removeWith(configure: (options: CheckpointRemoveOptions) => CheckpointRemoveOptions): Promise<CheckpointRemoveResult> {
    if (!this.inner.removeCheckpoint) throw new UnsupportedError("Checkpoint removal reports require an updated native library");
    const options = configure(new CheckpointRemoveOptions());
    const result = await withMappedErrors(() => this.inner.removeCheckpoint!(options.toNative()));
    return parseCheckpointRemoval(JSON.parse(result));
  }

  /** Capture a local destination; never changes ambient routing. */
  static local(): Checkpoints { return new LocalContext().checkpoints; }
  /** Capture remote environment credentials now, before creating or looking up a resource. */
  static remote(): Checkpoints { return RemoteContext.fromEnv().checkpoints; }
  static ctx(context: Context): Checkpoints { return context.checkpoints; }

  get context(): Context { return Context.fromNative(this.inner.context()); }

  /**
   * Begin building a snapshot on the configured backend; local names may be generated.
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
  static async get(nameOrDigest: string): Promise<Snapshot> {
    const raw = await withMappedErrors(() => napi.Snapshot.get(nameOrDigest));
    return new Snapshot(raw);
  }

  /** List snapshots visible through the active backend. */
  static async list(): Promise<Snapshot[]> {
    const infos = await withMappedErrors(() => napi.Snapshot.list());
    return infos.map((snapshot) => new Snapshot(snapshot));
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
    requireArchiveCompatibility(opts);
    await withMappedErrors(() => napi.Snapshot.save(nameOrPath, out, opts));
  }

  /**
   * Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
   * snapshots directory. Recorded payload integrity is preserved for
   * explicit verification. Compression is detected from magic bytes.
   */
  static async load(archive: string, dest?: string, base?: string): Promise<Snapshot> {
    const raw = await withMappedErrors(() => napi.Snapshot.load(archive, dest, base));
    return new Snapshot(raw);
  }

  /** Import into a selected or generated group, with optional head selection. */
  static async loadWithOptions(archive: string, opts: LoadOpts = {}): Promise<Snapshot> {
    if (opts.maximumDiskBytes != null && !napi.Snapshot.supportsImportBudget?.()) throw new UnsupportedError("Snapshot import size limits require an updated native SDK");
    const raw = await withMappedErrors(() => napi.Snapshot.loadWithOptions(archive, opts));
    return new Snapshot(raw);
  }

  /** Import archives together into one group, resolving dependencies regardless of input order. */
  static async loadMany(archives: string[], opts: LoadOpts = {}): Promise<Snapshot[]> {
    if (opts.maximumDiskBytes != null && !napi.Snapshot.supportsImportBudget?.()) throw new UnsupportedError("Snapshot import size limits require an updated native SDK");
    const raw = await withMappedErrors(() => napi.Snapshot.loadMany(archives, opts));
    return raw.map((handle) => new Snapshot(handle));
  }

  static async groupHead(group: string): Promise<string | null> {
    return (await withMappedErrors(() => napi.Snapshot.readGroupHead(group))) ?? null;
  }

  static async setGroupHead(group: string, id: string): Promise<HeadUpdate> {
    const update = await withMappedErrors(() => napi.Snapshot.setGroupHead(group, id));
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
    return update ? { ...update, previous: update.previous ?? null, head: update.head ?? null } : null;
  }

  /** Stable opaque snapshot identity. */
  get id(): string {
    return this.inner.id;
  }

  /** Captured name; operations retain the resource identity even if a path is reused. */
  get name(): string | null { return this.inner.name ?? null; }

  get group(): string | null { return this.inner.group ?? null; }

  /** Delete this captured identity; remote path snapshots require conditional deletion support. */
  async destroy(opts?: { force?: boolean }): Promise<void> {
    await withMappedErrors(() => this.inner.destroy(opts));
  }

  /** Captured index metadata from resource selection. */
  get parentDigest(): string | null { return this.inner.parentDigest ?? null; }

  /** Captured index metadata from resource selection. */
  get locality(): string { return this.inner.locality; }

  /** Captured index metadata from resource selection. */
  get availability(): string { return this.inner.availability; }

  /** Captured index metadata from resource selection. */
  get migrationState(): string { return this.inner.migrationState; }

  /** Captured index metadata from resource selection. */
  get migrationErrorCode(): string | null { return this.inner.migrationErrorCode ?? null; }

  /** SHA-256 digest of the canonical descriptor. */
  get digest(): string {
    return this.inner.digest;
  }

  /** Backend-reported stored payload size in bytes. */
  get sizeBytes(): bigint | null {
    return this.inner.sizeBytes ?? null;
  }

  /** Fetch the full normalized descriptor as a detached observation. */
  async manifest(): Promise<Readonly<Record<string, unknown>>> {
    return JSON.parse(await withMappedErrors(() => this.inner.manifest()));
  }

  /** Fetch one descriptor observation and project its state. */
  async state(): Promise<SnapshotState> {
    const metadata = await withMappedErrors(() => this.inner.metadata());
    if (metadata.stateKind === "checkpoint") {
      return {
        kind: "checkpoint",
        checkpointId: requiredProjectionString(
          metadata.checkpointId,
          "checkpointId",
        ),
        manifest: requiredProjectionString(
          metadata.checkpointManifestDigest,
          "checkpointManifestDigest",
        ),
      };
    }
    if (metadata.stateKind !== "file") {
      throw invalidProjection(`unknown stateKind ${metadata.stateKind}`);
    }

    const format = requiredProjectionString(metadata.format, "format");
    if (format !== "raw" && format !== "qcow2") {
      throw invalidProjection(`unknown file-state format ${format}`);
    }
    const sizeBytes = metadata.sizeBytes;
    if (typeof sizeBytes !== "bigint") {
      throw invalidProjection("missing file-state sizeBytes");
    }
    const algorithm = metadata.upperIntegrityAlgorithm;
    const value = metadata.upperIntegrityDigest;
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
        const logicalSize = metadata.upperIntegrityLogicalSize;
        const leafSize = metadata.upperIntegrityLeafSize;
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
      fstype: requiredProjectionString(metadata.fstype, "fstype"),
      upper: {
        file: requiredProjectionString(metadata.upperFile, "upperFile"),
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
  async imageManifestDigest(): Promise<string> {
    return (await withMappedErrors(() => this.inner.metadata())).imageManifestDigest;
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
  async labels(): Promise<ReadonlyArray<readonly [string, string]>> {
    return Object.entries(await withMappedErrors(() => this.inner.labels()));
  }

  /** Best-effort source-sandbox name, if recorded. */
  async sourceSandbox(): Promise<string | null> {
    return (await withMappedErrors(() => this.inner.metadata())).sourceSandbox ?? null;
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
  /** Export this exact checkpoint with default archive controls. */
  async save(out: string): Promise<void> { await this.saveTo(out); }

  /** Export this exact checkpoint with portable/incremental archive controls. */
  async saveWith(out: string, configure: (options: SnapshotSaveOptions) => SnapshotSaveOptions): Promise<void> {
    await this.saveTo(out, configure(new SnapshotSaveOptions()).toNative());
  }

  async spawnSandbox(): Promise<Sandbox> { return this.spawnSandboxWith(b => b); }

  async spawnSandboxWith(configure: (options: RestoreBuilder) => RestoreBuilder): Promise<Sandbox> {
    const builder = configure(Sandbox.restore(this));
    const sandbox = await withMappedErrors(() => this.inner.spawnSandboxWithBuilder(builder as unknown as NapiRestoreBuilder));
    return new Sandbox(sandbox, await sandbox.name);
  }

  async spawnSandboxWithProgress(): Promise<CreationProgressCreate> {
    return this.spawnSandboxWithProgressWith(b => b);
  }

  async spawnSandboxWithProgressWith(configure: (options: RestoreBuilder) => RestoreBuilder): Promise<CreationProgressCreate> {
    const builder = configure(Sandbox.restore(this));
    const progress = await withMappedErrors(() => this.inner.spawnSandboxWithProgressBuilder(builder as unknown as NapiRestoreBuilder));
    return new CreationProgressCreate(progress, "");
  }

  async saveTo(out: string, opts?: SaveOpts): Promise<void> {
    requireArchiveCompatibility(opts);
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

  /** Observe this artifact's storage using its captured backend. */
  async storageUsage(): Promise<StorageItemUsage> {
    return storageUsageFromHandle(this.inner, "Snapshot.storageUsage()");
  }
}

/** @internal */
export function wrapBuilder(nb: InstanceType<typeof napi.SnapshotBuilder>): SnapshotBuilder {
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
  let coverage: SnapshotVerifyCoverage;
  if (r.coverageKind == null) {
    // A head checksum from an older native library cannot prove ancestor/owned-disk coverage.
    coverage = { kind: "unknown" };
  } else if (r.coverageKind === "complete") {
    coverage = { kind: "complete" };
  } else if (r.coverageKind === "incomplete" && r.unrecorded?.length) {
    coverage = { kind: "incomplete", unrecorded: [...r.unrecorded] };
  } else {
    throw invalidProjection(`invalid verification coverage ${r.coverageKind}`);
  }
  const checkpoint =
    typeof r.checkpointRoot === "string"
      ? { kind: "verified" as const, root: r.checkpointRoot }
      : undefined;
  if (r.upperKind === "notRecorded") {
    return {
      digest: r.digest,
      path: r.path,
      upper: { kind: "notRecorded" },
      coverage,
      ...(checkpoint === undefined ? {} : { checkpoint }),
    };
  }
  if (r.upperKind === "verified") {
    return {
      digest: r.digest,
      path: r.path,
      coverage,
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
/** @internal Never let an older native option decoder silently ignore an explicit target. */
export function requireArchiveCompatibility(opts?: SaveOpts): void {
  if (opts?.compatibility !== undefined &&
      !napi.snapshotArchiveCompatibilityTargets?.().includes(opts.compatibility)) {
    throw new UnsupportedError("The requested archive compatibility target requires an updated native library");
  }
}
