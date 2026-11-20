import { UnsupportedError } from "./errors.js";
import { snapshotCreateResult, type SnapshotCreateResult, SnapshotCaptureOptions } from "./snapshot-group.js";
import type { SandboxConfigInspection } from "./config-inspection.js";
import { bindingFor } from "./internal/provider.js";
import { Snapshot } from "./snapshot.js";
import { storageUsageFromHandle, type StorageItemUsage } from "./storage.js";
import { Context, LocalContext, RemoteContext, Sandboxes } from "./context.js";
import { recoverStorage, type StorageRecovery, type StorageRecoveryOptions } from "./storage-recovery.js";
import { Job, JobListBuilder, jobCall, jobPageFromJson, type JobPage } from "./jobs.js";
import { remapKeysToCamel } from "./internal/config.js";
import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import { validateTimeoutMs } from "./internal/stop.js";
import { forkMountBuilders, type ForkVolumes } from "./internal/fork-volumes.js";
import {
  compactionResultFromJson,
  type DiskCompactionOptions,
  type DiskCompactionResult,
} from "./compact.js";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
  resizeStatusFromJson,
  validateResizeTimeout,
  requireModifyCapabilities,
  type ModifyOptions,
  type ResourceResizeStatus,
  type SandboxModificationPlan,
} from "./modify.js";
import {
  modificationResultFromJson,
  resizeOperationsFromJson,
  resizeOperationsToJson,
  type ResizeOperation,
  type SandboxModificationResult,
} from "./resize.js";
import {
  napi,
  type NapiAttachOptionsBuilder,
  type NapiExecOptionsBuilder,
  type NapiPullProgressCreate,
  type NapiPullProgressEvent,
  type NapiPullProgressStream,
  type NapiSandbox,
  type NapiSandboxBuilderSetters,
  type NapiRestoreBuilderSetters,
  type NapiRestoreBuilder,
  type NapiSandboxConfig,
  type NapiSandboxListOptions,
  type NapiSandboxPage,
  type NapiSnapshotSeed,
} from "./internal/napi.js";
import { ExecHandle, ExecOutput } from "./exec.js";
import { SandboxFsOps } from "./fs.js";
import {
  LogEntry,
  LogStream,
  type LogReadOptions,
  type LogStreamOptions,
  logEntryFromNapi,
  logReadOptionsToNapi,
  logStreamOptionsToNapi,
} from "./logs.js";
import {
  type DestroyOptions,
  type RestartOptions,
  type SandboxStopResult,
} from "./lifecycle.js";
import type { SandboxStatus } from "./sandbox-status.js";
import type { SandboxMetrics } from "./metrics.js";
import { metricsFromNapi } from "./internal/metrics.js";
import { MetricsStream } from "./metrics-stream.js";
import { SandboxSshOps } from "./ssh.js";

/**
 * Fluent builder for a sandbox. Returned by `Sandbox.builder(name)`.
 * Sandbox names are limited to 128 UTF-8 bytes.
 *
 * The instance IS the napi-rs `SandboxBuilder` class — every setter is a
 * native call, no TS-side reimplementation. Only the terminal `create()`
 * method is wrapped here so it returns a TS
 * `Sandbox` (which adds `Symbol.asyncDispose`, error-mapping, and a few
 * sync getters on top of the native handle).
 */
// `interface ... extends NapiSandboxBuilderSetters` is the form that
// preserves polymorphic `this` through chained calls — the napi
// builder is split into a setters-only base + a terminals interface
// (`internal/napi.ts`) precisely so we can extend the base here and
// add the TS-flavored terminals (which return TS `Sandbox` /
// `PullProgressCreate` instead of the napi shapes). An `Omit<...> &
// {...}` type alias would lose the override on every chained `this`
// return, leaving `b.image(...).create()` inferred as
// `Promise<NapiSandbox>`.
export type SandboxConfig = NapiSandboxConfig;

export type CpuPlacement = "inherit" | "auto" | "spread" | "compact";

export interface SandboxBuilder extends NapiSandboxBuilderSetters {
  /** Create a new sandbox, preserving strict name-conflict behavior. */
  create(): Promise<Sandbox>;
  /**
   * Connect to and run the persisted sandbox with this name, or create it if absent.
   * Builder options are used only for creation; existing configuration wins.
   */
  connectOrCreate(): Promise<Sandbox>;
  createWithPullProgress(): Promise<PullProgressCreate>;
  /** Image preparation, snapshot backing and activation progress. Await the result for success. */
  createWithProgress(): Promise<CreationProgressCreate>;
}

/** Restore a snapshot or archive as a detached sandbox with explicit host bindings. */
export interface RestoreBuilder extends NapiRestoreBuilderSetters {
  restore(): Promise<Sandbox>;
  restoreWithProgress(): Promise<CreationProgressCreate>;
}

export interface SandboxPingResult {
  readonly name: string;
  readonly latencyMs: number;
}

export interface SandboxTouchResult {
  readonly name: string;
  readonly activitySeq: number;
}

/** Options for forking a running sandbox. */
export interface ForkOptions {
  recordIntegrity?: boolean;
  guestFlush?: import("./snapshot.js").GuestFlush;
  /**
   * Rebind a captured disk at its guest path to a host image holding the captured
   * state; a fork cannot add a new block device. Each child attaches the image
   * directly, without a private copy, so batch forks should not share a writable image.
   */
  volumes?: ForkVolumes;
}

/** One named child or startup error from a capture-once batch, in input order. */
export type ForkOutcome =
  | { name: string; sandbox: Sandbox; error?: never }
  | { name: string; sandbox?: never; error: Error };

/** @deprecated Use ForkOutcome instead. */
export type BranchOutcome = ForkOutcome;

/** An unmapped external filesystem or a mismatch accepted during relaxed restore. */
export interface ExternalMountWarning {
  readonly guestPath: string;
  readonly reason: string;
  readonly staleInodes: readonly bigint[];
}

/** A single live backend observation; subsequent changes are not reflected here. */
export interface SandboxInfo {
  readonly id: string;
  readonly name: string;
  readonly status: SandboxStatus;
  readonly lastFailureMessage: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
}

/** One page returned by `Sandbox.list()` or `Sandbox.listWith()`. */
export interface SandboxPage {
  sandboxes: Sandbox[];
  nextCursor?: string;
}

/** Fluent options for one paginated sandbox list request. */
export class SandboxListBuilder {
  private readonly options: NapiSandboxListOptions = {};

  limit(limit: number): this {
    this.options.limit = limit;
    return this;
  }

  cursor(cursor: string): this {
    this.options.cursor = cursor;
    return this;
  }

  label(key: string, value: string): this {
    this.options.labels ??= {};
    this.options.labels[key] = value;
    return this;
  }

  labels(labels: Record<string, string>): this {
    this.options.labels = { ...this.options.labels, ...labels };
    return this;
  }

  /** @internal */
  toNapi(): NapiSandboxListOptions {
    return this.options;
  }
}

export function sandboxPageFromNapi(page: NapiSandboxPage): SandboxPage {
  return {
    sandboxes: page.sandboxes.map((resource) => new Sandbox(resource, resource.name)),
    nextCursor: page.nextCursor,
  };
}

/**
 * Pair returned by `SandboxBuilder.createWithPullProgress()` —
 * the per-layer progress event stream plus a method to await the
 * final `Sandbox`.
 */
export class PullProgressCreate {
  /** Cancel creation; awaitSandbox() rejects when cancellation is observed. */
  cancel(): void { this.inner.cancel(); }

  /** @internal */
  private readonly inner: NapiPullProgressCreate;
  /** @internal */
  private readonly name: string;
  /** @internal */
  constructor(inner: NapiPullProgressCreate, name: string, private readonly attachedCreation = false) {
    this.inner = inner;
    this.name = name;
  }

  /**
   * The progress event stream. Iterate with `for await...of` or poll
   * with `.recv()`. The stream closes once the pull completes.
   */
  get progress(): NapiPullProgressStream {
    return this.inner.progress;
  }

  /**
   * Async iterator helper: equivalent to `for await (const ev of c.progress)`.
   * Lets you write `for await (const ev of c) { … }` directly.
   */
  [Symbol.asyncIterator](): AsyncIterator<NapiPullProgressEvent> {
    return this.inner.progress[Symbol.asyncIterator]();
  }

  /** Await the sandbox. Resolves once pull + boot finishes. */
  async awaitSandbox(): Promise<Sandbox> {
    const inner = await withMappedErrors(() => this.inner.awaitSandbox());
    return new Sandbox(inner, await inner.name, this.attachedCreation);
  }
}

/** Creation-wide progress; ignoring events does not cancel or delay creation. */
export class CreationProgressCreate {
  private readonly creation: PullProgressCreate;
  /** @internal */
  constructor(inner: NapiPullProgressCreate, name: string, attachedCreation = false) {
    this.creation = new PullProgressCreate(inner, name, attachedCreation);
  }
  get progress(): import("./creation-progress.js").CreationProgressStream {
    return this.creation.progress as unknown as import("./creation-progress.js").CreationProgressStream;
  }
  [Symbol.asyncIterator](): AsyncIterator<import("./creation-progress.js").CreationProgress> {
    return this.progress[Symbol.asyncIterator]();
  }
  cancel(): void { this.creation.cancel(); }
  awaitSandbox(): Promise<Sandbox> { return this.creation.awaitSandbox(); }
}

/** An argument list may be an array, set or generator. A string is one argument. */
export type CommandArgs = Iterable<string> & object;

function commandArgs(args?: CommandArgs): string[] | undefined {
  if (typeof args === "string") {
    throw new TypeError("Pass command arguments as a list, for example ['argument'].");
  }
  return args === undefined ? undefined : Array.from(args);
}

export class Sandbox implements AsyncDisposable {

  /** Recover stopped storage after diagnosis. Never boots or stops a VM; originals are retained. */
  static async recoverStorage(name: string, options: StorageRecoveryOptions = {}): Promise<StorageRecovery> {
    return recoverStorage(name, options);
  }

  async snapshot(group: string): Promise<SnapshotCreateResult> {
    return this.snapshotWith(group, options => options);
  }

  async snapshotWith(group: string, configure: (options: SnapshotCaptureOptions) => SnapshotCaptureOptions): Promise<SnapshotCreateResult> {
    const options = configure(new SnapshotCaptureOptions()).toNative();
    return snapshotCreateResult(await withMappedErrors(() => this.inner.snapshot(group, options)));
  }

  async getJob(id: string): Promise<Job> { return new Job(await jobCall(() => this.inner.getJob(id))); }
  async listJobs(): Promise<JobPage> { return this.listJobsWith(b => b); }
  async listJobsWith(configure: (b: JobListBuilder) => JobListBuilder): Promise<JobPage> {
    const b = configure(new JobListBuilder());
    return jobPageFromJson(await jobCall(() => this.inner.listJobs(b.includeAll, b.pageSize, b.after)));
  }

  async execDetached(cmd: string, args?: CommandArgs): Promise<Job> {
    const argv = commandArgs(args) ?? [];
    return new Job(await jobCall(() => this.inner.execDetached(cmd, argv)));
  }
  async execDetachedWith(cmd: string, configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder): Promise<Job> {
    const builder = configure(new (bindingFor(this.inner, napi).ExecOptionsBuilder)().stdinPipe());
    return new Job(await jobCall(() => this.inner.execDetachedWithBuilder(cmd, builder)));
  }

  /** Prepare restoration; no VM starts until the builder's restore terminal. */
  static restore(snapshot: NapiSnapshotSeed): RestoreBuilder {
    const builder = typeof snapshot === "string"
      ? new napi.RestoreBuilder(snapshot)
      : new napi.RestoreBuilder(snapshot.reference, snapshot.referenceKind);
    return Sandbox.fromNativeRestoreBuilder(builder);
  }

  /** @internal Wrap terminals without replacing the native builder's retained destination. */
  static fromNativeRestoreBuilder(builder: NapiRestoreBuilder): RestoreBuilder {
    // A new JS package can load an older native addon. Reject explicit unsupported policy
    // instead of dropping it; ordinary restores still use the old supported entry points.
    if (typeof builder.guestClock !== "function") {
      builder.guestClock = () => { throw new UnsupportedError("guest clock selection requires an updated native SDK"); };
    }
    for (const option of ["init", "initWith", "hostname", "maxCpus", "maxMemory", "label", "labels", "workdir", "shell", "entrypoint", "cmd", "env", "envs", "proxy", "pullPolicy"] as const) {
      if (typeof builder[option] !== "function") {
        builder[option] = () => { throw new UnsupportedError(`${option} selection requires an updated native SDK`); };
      }
    }
    const restore = builder.restore.bind(builder);
    const progress = builder.restoreWithProgress.bind(builder);
    let name = "";
    const setName = builder.name.bind(builder);
    builder.name = (value: string) => {
      setName(value);
      name = value;
      return builder;
    };
    (builder as unknown as RestoreBuilder).restore = async () =>
      new Sandbox(await withMappedErrors(restore), name);
    (builder as unknown as RestoreBuilder).restoreWithProgress = async () =>
      new CreationProgressCreate(await withMappedErrors(progress), name);
    return builder as unknown as RestoreBuilder;
  }

  /** @internal */
  readonly inner: NapiSandbox;
  /** Sandbox name. Names are limited to 128 UTF-8 bytes. */
  readonly name: string;
  /** Stable identity that changes when this name is removed and recreated. */
  readonly id: string;
  /** Whether this handle acquired cleanup ownership for its scope. */
  get ownsLifecycle(): boolean {
    return this.contextKind === "local" ? this.inner.ownsLifecycle : this.stopRemoteOnDispose;
  }
  /** Backend retained by this sandbox. */
  readonly contextKind: "local" | "remote";

  private stopRemoteOnDispose: boolean;

  /** @internal use `Sandbox.builder(name).create()` */
  constructor(
    inner: NapiSandbox,
    name: string,
    attachedCreation = false,
  ) {
    this.inner = inner;
    this.name = name;
    this.id = inner.id;
    this.contextKind = inner.backendKind === "local" ? "local" : "remote";
    // Only the creating wrapper owns the remote stop request. Local ownership
    // stays native so detach and automatic local launch modes remain observable.
    this.stopRemoteOnDispose = this.contextKind === "remote" && attachedCreation;
  }

  // -- statics ------------------------------------------------------------

  /** Capture a local destination; never changes ambient routing. */
  static local(): Sandboxes { return new LocalContext().sandboxes; }
  /** Capture remote environment credentials now, before creating or looking up a resource. */
  static remote(): Sandboxes { return RemoteContext.fromEnv().sandboxes; }
  static ctx(context: Context): Sandboxes { return context.sandboxes; }

  get context(): Context { return Context.fromNative(this.inner.context()); }

  /** Begin building a sandbox on the configured backend. Names are limited to 128 UTF-8 bytes. */
  static builder(name: string): SandboxBuilder {
    return Sandbox.fromNativeBuilder(name, new napi.SandboxBuilder(name));
  }

  /** @internal Wrap native terminals without changing the builder's destination. */
  static fromNativeBuilder(name: string, nb: InstanceType<typeof napi.SandboxBuilder>): SandboxBuilder {
    const origCreate = nb.create.bind(nb);
    const origConnectOrCreate = nb.connectOrCreate.bind(nb);
    const origCreateWithPP = nb.createWithPullProgress.bind(nb);
    const origCreateWithProgress = nb.createWithProgress?.bind(nb);
    const setDetached = nb.detached.bind(nb);
    let detached = false;
    nb.detached = (enabled: boolean) => {
      const result = setDetached(enabled);
      detached = enabled;
      return result;
    };
    // Capture the mode when each creation starts, including progress sessions.
    (nb as unknown as { create: () => Promise<Sandbox> }).create = async () => {
      const attached = !detached;
      const inner = await withMappedErrors(() => origCreate());
      return new Sandbox(inner, name, attached);
    };
    (
      nb as unknown as { connectOrCreate: () => Promise<Sandbox> }
    ).connectOrCreate = async () => {
      const inner = await withMappedErrors(() => origConnectOrCreate());
      // An existing running sandbox is connected without taking ownership,
      // while a newly created or restarted sandbox follows detached mode.
      return new Sandbox(inner, name);
    };
    (
      nb as unknown as {
        createWithPullProgress: () => Promise<PullProgressCreate>;
      }
    ).createWithPullProgress = async () => {
      const attached = !detached;
      const raw = await withMappedErrors(() => origCreateWithPP());
      return new PullProgressCreate(raw, name, attached);
    };
    (nb as unknown as { createWithProgress: () => Promise<CreationProgressCreate> }).createWithProgress = async () => {
      if (!origCreateWithProgress) throw new Error("Installed native SDK does not support creation progress");
      const attached = !detached;
      const raw = await withMappedErrors(() => origCreateWithProgress());
      return new CreationProgressCreate(raw, name, attached);
    };
    return nb as unknown as SandboxBuilder;
  }

  /**
   * Resume an existing stopped sandbox in attached mode.
   * Names are limited to 128 UTF-8 bytes.
   */
  static async start(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() => napi.Sandbox.start(name));
    return new Sandbox(inner, name);
  }

  /**
   * Resume an existing stopped sandbox in detached mode.
   * Names are limited to 128 UTF-8 bytes.
   */
  static async startDetached(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() =>
      napi.Sandbox.startDetached(name),
    );
    return new Sandbox(inner, name);
  }

  /**
   * Look up an existing sandbox without starting it.
   * Names are limited to 128 UTF-8 bytes.
   */
  static async get(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() => napi.Sandbox.get(name));
    return new Sandbox(inner, name);
  }

  /** Get an existing sandbox and connect or start it; never creates a missing resource. */
  static async getRunning(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() => napi.Sandbox.getRunning(name));
    return new Sandbox(inner, name);
  }

  /** List the first page of known sandboxes. */
  static async list(): Promise<SandboxPage> {
    const page = await withMappedErrors(() => napi.Sandbox.list());
    return sandboxPageFromNapi(page);
  }

  /** List a configured page of sandboxes. */
  static async listWith(
    configure: (list: SandboxListBuilder) => SandboxListBuilder,
  ): Promise<SandboxPage> {
    const options = configure(new SandboxListBuilder()).toNapi();
    const page = await withMappedErrors(() =>
      napi.Sandbox.listWith(options),
    );
    return sandboxPageFromNapi(page);
  }

  /**
   * Remove a stopped sandbox from the database.
   * Names are limited to 128 UTF-8 bytes.
   */
  static async remove(name: string): Promise<void> {
    await withMappedErrors(() => napi.Sandbox.remove(name));
  }

  // -- exec ---------------------------------------------------------------

  async execDefault(): Promise<ExecOutput> {
    const raw = await withMappedErrors(() => this.inner.execDefault());
    return new ExecOutput(raw);
  }

  async execDefaultWith(
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecOutput> {
    const builder = configure(new (bindingFor(this.inner, napi).ExecOptionsBuilder)());
    const raw = await withMappedErrors(() =>
      this.inner.execDefaultWithBuilder(builder),
    );
    return new ExecOutput(raw);
  }

  async execDefaultStream(): Promise<ExecHandle> {
    const raw = await withMappedErrors(() => this.inner.execDefaultStream());
    return new ExecHandle(raw);
  }

  async execDefaultStreamWith(
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecHandle> {
    const builder = configure(new (bindingFor(this.inner, napi).ExecOptionsBuilder)());
    const raw = await withMappedErrors(() =>
      this.inner.execDefaultStreamWithBuilder(builder),
    );
    return new ExecHandle(raw);
  }

  async exec(cmd: string, args?: CommandArgs): Promise<ExecOutput> {
    const argv = commandArgs(args);
    const raw = await withMappedErrors(() => this.inner.exec(cmd, argv));
    return new ExecOutput(raw);
  }

  async execWith(
    cmd: string,
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecOutput> {
    const builder = configure(new (bindingFor(this.inner, napi).ExecOptionsBuilder)());
    const raw = await withMappedErrors(() =>
      this.inner.execWithBuilder(cmd, builder),
    );
    return new ExecOutput(raw);
  }

  async execStream(cmd: string, args?: CommandArgs): Promise<ExecHandle> {
    const argv = commandArgs(args);
    const raw = await withMappedErrors(() =>
      this.inner.execStream(cmd, argv),
    );
    return new ExecHandle(raw);
  }

  async execStreamWith(
    cmd: string,
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecHandle> {
    const builder = configure(new (bindingFor(this.inner, napi).ExecOptionsBuilder)());
    const raw = await withMappedErrors(() =>
      this.inner.execStreamWithBuilder(cmd, builder),
    );
    return new ExecHandle(raw);
  }

  async shell(script: string): Promise<ExecOutput> {
    const raw = await withMappedErrors(() => this.inner.shell(script));
    return new ExecOutput(raw);
  }

  async shellStream(script: string): Promise<ExecHandle> {
    const raw = await withMappedErrors(() => this.inner.shellStream(script));
    return new ExecHandle(raw);
  }

  // -- attach -------------------------------------------------------------

  async attachDefault(): Promise<number> {
    return await withMappedErrors(() => this.inner.attachDefault());
  }

  async attachDefaultWith(
    configure: (b: NapiAttachOptionsBuilder) => NapiAttachOptionsBuilder,
  ): Promise<number> {
    const builder = configure(new (bindingFor(this.inner, napi).AttachOptionsBuilder)());
    return await withMappedErrors(() =>
      this.inner.attachDefaultWithBuilder(builder),
    );
  }

  async attach(cmd: string, args?: CommandArgs): Promise<number> {
    const argv = commandArgs(args);
    return await withMappedErrors(() => this.inner.attach(cmd, argv));
  }

  async attachWith(
    cmd: string,
    configure: (b: NapiAttachOptionsBuilder) => NapiAttachOptionsBuilder,
  ): Promise<number> {
    const builder = configure(new (bindingFor(this.inner, napi).AttachOptionsBuilder)());
    return await withMappedErrors(() =>
      this.inner.attachWithBuilder(cmd, builder),
    );
  }

  async attachShell(): Promise<number> {
    return await withMappedErrors(() => this.inner.attachShell());
  }

  // -- filesystem ---------------------------------------------------------

  fs(): SandboxFsOps {
    return new SandboxFsOps(this.inner.fs());
  }

  // -- ssh ----------------------------------------------------------------

  ssh(): SandboxSshOps {
    return new SandboxSshOps(this.inner.ssh());
  }

  // -- config -------------------------------------------------------------

  /** Prepare this receiver, retaining any local run it starts. */
  async ensureRunning(): Promise<void> {
    await withMappedErrors(() => this.inner.ensureRunning());
  }

  /** Fetch related mutable fields together without preparing the runtime. */
  async info(): Promise<SandboxInfo> {
    const raw = JSON.parse(await withMappedErrors(() => this.inner.infoJson()));
    return {
      id: raw.id, name: raw.name, status: raw.status,
      lastFailureMessage: raw.last_failure_message,
      createdAt: raw.created_at,
      updatedAt: raw.updated_at,
    };
  }

  async status(): Promise<SandboxStatus> {
    return (await this.info()).status;
  }

  async lastFailureMessage(): Promise<string | null> {
    return (await this.info()).lastFailureMessage;
  }

  /** Fetch the latest persisted settings; these may still require a restart to apply. */
  async config(): Promise<SandboxConfigInspection> {
    const json = await withMappedErrors(() => this.inner.configJson());
    const view = remapKeysToCamel(JSON.parse(json));
    if (view.kind === "local") {
      // Local specs persist Rust variant names. Builders accept kebab-case values.
      const policy: string = view.spec.pullPolicy;
      view.spec.pullPolicy = policy === "IfMissing" ? "if-missing" : policy.toLowerCase();
    }
    return view as SandboxConfigInspection;
  }

  // -- logs ---------------------------------------------------------------

  /**
   * Read captured output from this sandbox's `exec.log`.
   *
   * Backed by an on-disk JSON Lines file the runtime writes via the
   * relay tap. Works on running and stopped sandboxes alike — no
   * protocol traffic. Default sources are user output: `stdout`,
   * `stderr`, and pty-merged `output`.
   */
  async logs(opts?: LogReadOptions): Promise<LogEntry[]> {
    const napiOpts = logReadOptionsToNapi(opts);
    const raw = await withMappedErrors(() => this.inner.logs(napiOpts));
    return raw.map(logEntryFromNapi);
  }

  /**
   * Stream captured output as it appears, with optional follow.
   *
   * Backed by the same on-disk `exec.log` as {@link logs}, but
   * yields entries lazily. Pass `{ follow: true }` to keep the
   * stream open past current EOF and pick up new entries as they
   * are written; otherwise the stream drains the current contents
   * and ends. Each yielded {@link LogEntry} carries an opaque
   * `cursor` that can be passed back via
   * {@link LogStreamOptions.fromCursor} to resume.
   */
  async logStream(opts?: LogStreamOptions): Promise<LogStream> {
    const napiOpts = logStreamOptionsToNapi(opts);
    const raw = await withMappedErrors(() => this.inner.logStream(napiOpts));
    return new LogStream(raw);
  }

  // -- metrics ------------------------------------------------------------

  async metrics(): Promise<SandboxMetrics> {
    const raw = await withMappedErrors(() => this.inner.metrics());
    return metricsFromNapi(raw);
  }

  /**
   * Check whether agentd is reachable without refreshing idle activity.
   */
  async ping(): Promise<SandboxPingResult> {
    return await withMappedErrors(() => this.inner.ping());
  }

  /**
   * Explicitly refresh this sandbox's idle activity timer.
   */
  async touch(): Promise<SandboxTouchResult> {
    return await withMappedErrors(() => this.inner.touch());
  }

  /**
   * Plan or apply a sandbox modification. With `dryRun: true` the plan is
   * computed without applying anything.
   */
  async modify(opts?: ModifyOptions): Promise<SandboxModificationPlan> {
    requireModifyCapabilities(opts, bindingFor(this.inner, napi));
    const raw = await withMappedErrors(() =>
      this.inner.modify(modifyOptionsToNapi(opts)),
    );
    return modificationPlanFromJson(raw);
  }

  /** Apply once and retain this call's operation identities; ordinary modify() is unchanged. */
  async modifyWithResizeTracking(opts?: ModifyOptions): Promise<SandboxModificationResult> {
    if (typeof this.inner.modifyWithResizeTracking !== "function") {
      throw new Error("resize operation tracking requires an updated native library");
    }
    requireModifyCapabilities(opts);
    return modificationResultFromJson(await withMappedErrors(() =>
      this.inner.modifyWithResizeTracking!(modifyOptionsToNapi(opts)),
    ));
  }

  /** Read current operation identities and evidence without changing targets. */
  async resizeOperations(): Promise<ResizeOperation[]> {
    if (typeof this.inner.resizeOperations !== "function") {
      throw new Error("resize operation tracking requires an updated native library");
    }
    return resizeOperationsFromJson(await withMappedErrors(() => this.inner.resizeOperations!()));
  }

  /** Wait for supplied identities. Timeout ends waiting only; later targets cannot replace them. */
  async waitForResizeOperations(
    operations: readonly ResizeOperation[], timeoutMs?: number,
  ): Promise<ResourceResizeStatus[]> {
    validateResizeTimeout(timeoutMs);
    const raw = resizeOperationsToJson(operations);
    if (typeof this.inner.waitForResizeOperations !== "function") {
      throw new Error("resize operation tracking requires an updated native library");
    }
    return resizeStatusFromJson(await withMappedErrors(() =>
      this.inner.waitForResizeOperations!(raw, timeoutMs),
    ));
  }

  /** Read retained CPU and memory resize status. Rejects a stopped sandbox or unsupported runtime. */
  async resizeStatus(): Promise<ResourceResizeStatus[]> {
    return resizeStatusFromJson(
      await withMappedErrors(() => this.inner.resizeStatus()),
    );
  }

  /**
   * Wait for the operations selected at the first read to be guest-confirmed.
   * Stopped, unsupported, superseded or unavailable history is not success.
   * Omitted waits without a deadline and keeps polling while a guest
   * never converges; `0` checks once. Expiry throws `ResizeTimeoutError`, whose
   * `status` is empty if no read completed before the deadline.
   */
  async waitUntilResized(timeoutMs?: number): Promise<ResourceResizeStatus[]> {
    validateResizeTimeout(timeoutMs);
    return resizeStatusFromJson(
      await withMappedErrors(() => this.inner.waitUntilResized(timeoutMs)),
    );
  }

  /** Compact sealed root and owned-data disk layers without rewriting existing snapshots. */
  async compact(opts?: DiskCompactionOptions): Promise<DiskCompactionResult> {
    const raw = await withMappedErrors(() =>
      this.inner.compact(opts?.layers, opts?.dryRun, opts?.disk, opts?.rootDiskOnly),
    );
    return compactionResultFromJson(raw);
  }

  /** Stream metrics snapshots at the given interval (in milliseconds). */
  async metricsStream(intervalMs: number): Promise<MetricsStream> {
    const raw = await withMappedErrors(() =>
      this.inner.metricsStream(intervalMs),
    );
    return new MetricsStream(raw);
  }

  // -- lifecycle ----------------------------------------------------------

  /** Read warnings for unmapped external filesystems and accepted restore mismatches. */
  async restoreWarnings(): Promise<ExternalMountWarning[]> {
    return withMappedErrors(() => this.inner.restoreWarnings());
  }

  /** Wait indefinitely for graceful completion and runtime ownership release; never implicitly kills. */
  async stop(): Promise<void> {
    await withMappedErrors(() => this.inner.stop());
  }

  /** @deprecated Use fork() for live execution duplication. */
  async branch(name: string, options: ForkOptions = {}): Promise<Sandbox> {
    return this.fork(name, options);
  }

  /** @deprecated Use forkMany() for capture-once live duplication. */
  async branchMany(names: string[], options: ForkOptions = {}): Promise<ForkOutcome[]> {
    return this.forkMany(names, options);
  }

  /** Create an independent local CoW child without a durable full snapshot. */
  async fork(name: string, options: ForkOptions = {}): Promise<Sandbox> {
    const volumes = forkMountBuilders(options.volumes, bindingFor(this.inner, napi));
    const child = await withMappedErrors(() => this.inner.fork(
      name, options.recordIntegrity, options.guestFlush, volumes.length > 0 ? volumes : undefined,
    ));
    return new Sandbox(child, name);
  }

  /** Capture once; return each named child's startup outcome in input order. */
  async forkMany(names: string[], options: ForkOptions = {}): Promise<ForkOutcome[]> {
    const volumes = forkMountBuilders(options.volumes, bindingFor(this.inner, napi));
    const outcomes = await withMappedErrors(() => this.inner.forkMany(
      names, options.recordIntegrity, options.guestFlush, volumes.length > 0 ? volumes : undefined,
    ));
    return outcomes.map(o => o.sandbox
      ? { name: o.name, sandbox: new Sandbox(o.sandbox, o.name) }
      : { name: o.name, error: mapNapiError(new Error(o.error ?? "Child startup failed")) as Error });
  }

  /** Suspend this resident VM without creating a snapshot. */
  async pause(options: { guestFlush?: import("./snapshot.js").GuestFlush } = {}): Promise<void> {
    await withMappedErrors(() => this.inner.pause(options.guestFlush));
  }

  /** Explicit resident resume; no snapshot is created. */
  async resume(): Promise<void> {
    await withMappedErrors(() => this.inner.resume());
  }

  async requestStop(): Promise<void> {
    await withMappedErrors(() => this.inner.requestStop());
  }

  /** One total budget; StopTimeoutError on expiry without killing. Zero never dispatches shutdown. */
  async stopWithTimeout(timeoutMs: number): Promise<void> {
    validateTimeoutMs(timeoutMs, "stop");
    await withMappedErrors(() => this.inner.stopWithTimeout(timeoutMs));
  }

  async kill(): Promise<void> {
    await withMappedErrors(() => this.inner.kill());
  }

  async requestKill(): Promise<void> {
    await withMappedErrors(() => this.inner.requestKill());
  }

  /** Force-kill with an integer observation timeout from 0 to 4294967295 milliseconds. */
  async killWithTimeout(timeoutMs: number): Promise<void> {
    validateTimeoutMs(timeoutMs, "kill");
    await withMappedErrors(() => this.inner.killWithTimeout(timeoutMs));
  }

  async requestDrain(): Promise<void> {
    await withMappedErrors(() => this.inner.requestDrain());
  }

  /**
   * Wait until this exact persisted sandbox reaches `status`.
   *
   * This method has no built-in timeout. A same-name replacement is rejected
   * instead of silently redirecting the wait to the new identity.
   */
  /** Capture this resource's stable identity in its retained context. */
  async checkpoint(name: string): Promise<Snapshot> {
    return new Snapshot(await withMappedErrors(() => this.inner.checkpoint(name)));
  }

  async storageUsage(): Promise<StorageItemUsage> {
    return storageUsageFromHandle(this.inner, "Sandbox.storageUsage()");
  }

  async waitForStatus(status: SandboxStatus): Promise<void> {
    await withMappedErrors(() => this.inner.waitForStatus(status));
  }

  /**
   * Stop and start this exact persisted sandbox.
   *
   * Graceful shutdown and a ten-second convergence timeout are the defaults.
   * A created, stopped, or crashed sandbox starts directly.
   */
  async restart(options?: RestartOptions): Promise<Sandbox> {
    const raw = await withMappedErrors(() => this.inner.restart(options));
    return new Sandbox(raw, this.name);
  }

  /**
   * Stop and remove this exact persisted sandbox.
   *
   * Graceful shutdown and a ten-second convergence timeout are the defaults.
   * The identity check refuses to remove a same-name replacement.
   */
  async destroy(options?: DestroyOptions): Promise<void> {
    await withMappedErrors(() => this.inner.destroy(options));
  }

  async waitUntilStopped(): Promise<SandboxStopResult> {
    return sandboxStopResultFromNapi(
      await withMappedErrors(() => this.inner.waitUntilStopped()),
    );
  }

  /**
   * Disarm shared automatic cleanup without consuming this sandbox.
   * Repeated calls succeed; guest operations and explicit stop remain available.
   */
  async detach(): Promise<void> {
    await withMappedErrors(() => this.inner.detach());
    this.stopRemoteOnDispose = false;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    if (!this.ownsLifecycle) return;
    if (this.stopRemoteOnDispose) {
      this.stopRemoteOnDispose = false;
      try {
        await this.stop();
      } catch {
        // Remote scope exit has always been best-effort. Explicit stop reports errors.
      }
      return;
    }
    // The native owner checks its captured run, so an old scope cannot stop a
    // restarted sandbox. Let await-using preserve body and cleanup errors.
    await withMappedErrors(() => this.inner.shutdownOwned());
  }
}

function sandboxStopResultFromNapi(result: {
  name: string;
  status: string;
  exitCode?: number | null;
  signal?: number | null;
  observedAt: number;
  source?: string | null;
}): SandboxStopResult {
  return {
    name: result.name,
    status: result.status as SandboxStopResult["status"],
    exitCode: result.exitCode ?? null,
    signal: result.signal ?? null,
    observedAt: new Date(result.observedAt),
    source: result.source ?? null,
  };
}
