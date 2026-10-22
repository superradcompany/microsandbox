import { parseGroupInfo, type SnapshotGroupInfo } from "./snapshot-inspection.js";
import { UnsupportedError } from "./errors.js";
import { parseGroupRemoval, type SnapshotRemoveResult } from "./snapshot-removal.js";
import type { NapiRestoreBuilder, NapiLoadOpts } from "./internal/napi.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import { napi, type NapiSnapshotGroup, type NapiSnapshotCreateResult, type NapiSnapshotCaptureOptions, type NapiHeadUpdate } from "./internal/napi.js";
import { Snapshot as Checkpoint, type HeadUpdate } from "./snapshot.js";
import { SnapshotHandle as CheckpointHandle } from "./snapshot-handle.js";
import { Sandbox, CreationProgressCreate, type RestoreBuilder } from "./sandbox.js";
import { parseGroupVerification, type SnapshotGroupVerifyReport } from "./snapshot-verification.js";

/** Controls for capturing one immutable member of a source-bound history. */
export class SnapshotCaptureOptions {
  private options: NapiSnapshotCaptureOptions = {};
  name(value: string): this { this.options.name = value; return this; }
  initialCheckpoint(value: string): this { return this.name(value); }
  destDir(value: string): this { this.options.destDir = value; return this; }
  full(): this { this.options.full = true; return this; }
  recordIntegrity(): this { this.options.recordIntegrity = true; return this; }
  guestFlush(value: "auto" | "required" | "skip"): this { this.options.guestFlush = value; return this; }
  label(key: string, value: string): this {
    this.options.labels = { ...this.options.labels, [key]: value };
    return this;
  }
  /** @internal Copy options so later builder changes cannot change an admitted capture. */
  toNative(): NapiSnapshotCaptureOptions {
    return { ...this.options, ...(this.options.labels ? {labels: {...this.options.labels}} : {}) };
  }
}

/** A new group and the exact checkpoint returned by the initial capture. */
export interface SnapshotCreateResult {
  readonly snapshot: Snapshot;
  readonly checkpoint: Checkpoint;
  readonly headUpdate: HeadUpdate;
}

/** The artifact and head outcome belonging to one capture operation. */
export interface CheckpointCaptureResult {
  readonly checkpoint: Checkpoint;
  readonly headUpdate: HeadUpdate;
}

/** Controls for one atomic import into the separately selected destination group. */
export class SnapshotLoadOptions {
  private options: NapiLoadOpts = {};
  base(value: string): this { this.options.base = value; return this; }
  destDir(value: string): this { this.options.dest = value; return this; }
  setHead(): this { this.options.setHead = true; return this; }
  /** @internal */
  toNative(): NapiLoadOpts { return { ...this.options }; }
}

/** Operation-owned facts from a confirmed atomic import. */
export interface SnapshotImportResult {
  readonly operationId: string;
  readonly snapshot: Snapshot;
  readonly checkpoints: CheckpointHandle[];
  readonly added: string[];
  readonly reused: string[];
  readonly headUpdate: HeadUpdate;
  readonly warnings: string[];
}

/** Named checkpoint history; its head is resolved when an operation begins. */
export class Snapshot {
  /** @internal */
  constructor(readonly inner: NapiSnapshotGroup) {}

  /** Observe the history and its exact saved source association. */
  async inspect(): Promise<SnapshotGroupInfo> {
    if (!this.inner.inspectJson) throw new UnsupportedError("Group inspection requires an updated native library");
    return parseGroupInfo(JSON.parse(await withMappedErrors(() => this.inner.inspectJson!())));
  }

  /** Remove the entire history, refusing active readers and surviving external dependents. */
  async remove(): Promise<SnapshotRemoveResult> {
    if (!this.inner.removeGroup) throw new UnsupportedError("Group removal requires an updated native library");
    const result = await withMappedErrors(() => this.inner.removeGroup!());
    return parseGroupRemoval(JSON.parse(result));
  }

  /** Verify every selected member. Failures reject with a SnapshotVerificationError and report. */
  async verify(): Promise<SnapshotGroupVerifyReport> {
    return parseGroupVerification(JSON.parse(await withMappedErrors(() => this.inner.verifyJson())));
  }

  static async load(group: string, files: string[]): Promise<SnapshotImportResult> {
    return Snapshot.loadWith(group, files, options => options);
  }

  static async loadWith(group: string, files: string[], configure: (options: SnapshotLoadOptions) => SnapshotLoadOptions): Promise<SnapshotImportResult> {
    const options = configure(new SnapshotLoadOptions()).toNative();
    const result = await withMappedErrors(() => napi.SnapshotGroup.load(group, [...files], options));
    return { operationId: result.operationId, snapshot: new Snapshot(result.snapshot),
      checkpoints: result.checkpoints.map(member => new CheckpointHandle(member)),
      added: [...result.added], reused: [...result.reused], headUpdate: headOutcome(result.headUpdate), warnings: [...result.warnings] };
  }

  static async get(name: string): Promise<Snapshot> {
    return new Snapshot(await withMappedErrors(() => napi.SnapshotGroup.get(name)));
  }

  static async list(): Promise<Snapshot[]> {
    return (await withMappedErrors(() => napi.SnapshotGroup.list())).map((group) => new Snapshot(group));
  }

  /** @deprecated Open a group and use head() or setHead(member). */
  static async groupHead(selector: string): Promise<HeadUpdate> {
    return headOutcome(await withMappedErrors(() => napi.Snapshot.groupHead(selector)));
  }

  get name(): string { return this.inner.name; }

  async head(): Promise<Checkpoint | null> {
    const value = await withMappedErrors(() => this.inner.head());
    return value ? new Checkpoint(value) : null;
  }

  async checkpoints(): Promise<CheckpointHandle[]> {
    return (await withMappedErrors(() => this.inner.checkpoints())).map((member) => new CheckpointHandle(member));
  }

  async getCheckpoint(member: string): Promise<Checkpoint> {
    return new Checkpoint(await withMappedErrors(() => this.inner.getCheckpoint(member)));
  }

  async setHead(member: string): Promise<HeadUpdate> {
    return headOutcome(await withMappedErrors(() => this.inner.setHead(member)));
  }

  async clearHead(): Promise<HeadUpdate> {
    return headOutcome(await withMappedErrors(() => this.inner.clearHead()));
  }

  async checkpoint(): Promise<CheckpointCaptureResult> { return this.checkpointWith((options) => options); }

  async checkpointWith(configure: (options: SnapshotCaptureOptions) => SnapshotCaptureOptions): Promise<CheckpointCaptureResult> {
    const options = configure(new SnapshotCaptureOptions()).toNative();
    const result = await withMappedErrors(() => this.inner.checkpoint(options));
    return { checkpoint: new Checkpoint(result.checkpoint), headUpdate: headOutcome(result.headUpdate) };
  }

  async spawnSandbox(): Promise<Sandbox> { return this.spawnSandboxWith(b => b); }

  async spawnSandboxWith(configure: (options: RestoreBuilder) => RestoreBuilder): Promise<Sandbox> {
    // Only destination options are passed native-side. Head selection stays inside the
    // receiver operation, so a callback cannot switch groups or backends.
    const builder = configure(Sandbox.restore(""));
    const sandbox = await withMappedErrors(() => this.inner.spawnSandboxWithBuilder(builder as unknown as NapiRestoreBuilder));
    return new Sandbox(sandbox, await sandbox.name);
  }
  async spawnSandboxWithProgress(): Promise<CreationProgressCreate> {
    return this.spawnSandboxWithProgressWith(b => b);
  }

  async spawnSandboxWithProgressWith(configure: (options: RestoreBuilder) => RestoreBuilder): Promise<CreationProgressCreate> {
    const builder = configure(Sandbox.restore(""));
    const progress = await withMappedErrors(() => this.inner.spawnSandboxWithProgressBuilder(builder as unknown as NapiRestoreBuilder));
    return new CreationProgressCreate(progress, "");
  }
}

/** @internal Normalize native optional values without losing an explicitly cleared head. */
export function headOutcome(update: NapiHeadUpdate): HeadUpdate {
  return { ...update, previous: update.previous ?? null, head: update.head ?? null };
}

/** @internal Do not reread the group's mutable head to construct capture results. */
export function snapshotCreateResult(result: NapiSnapshotCreateResult): SnapshotCreateResult {
  return { snapshot: new Snapshot(result.snapshot), checkpoint: new Checkpoint(result.checkpoint), headUpdate: headOutcome(result.headUpdate) };
}
