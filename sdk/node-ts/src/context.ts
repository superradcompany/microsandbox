import { UnsupportedError } from "./errors.js";
import { binding, defaultBinding, nativeOwner } from "./internal/provider.js";
import { type NapiSnapshotSeed, type NapiContext } from "./internal/napi.js";
import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import { Sandbox, SandboxListBuilder, sandboxPageFromNapi, type RestoreBuilder, type SandboxBuilder, type SandboxPage } from "./sandbox.js";
import { Volume, type VolumeBuilder } from "./volume.js";
import { Snapshot as Group, SnapshotLoadOptions, wrapImportResult, type SnapshotImportResult } from "./snapshot-group.js";
import { Snapshot, wrapBuilder, type SnapshotBuilder, type HeadUpdate } from "./snapshot.js";

/** Secret-safe metadata captured with a destination. */
export interface ContextInfo {
  readonly kind: "local" | "remote";
  readonly source: string;
  readonly profile?: string;
  readonly apiUrl?: string;
}

/** Resolve once; later configuration changes do not redirect this context. */
export function configuredContext(): Context {
  try {
    const native = defaultBinding().configuredContext();
    return native.kind === "remote" ? RemoteContext.fromNative(native) : Context.fromNative(native);
  } catch (error) { throw mapNapiError(error); }
}

export interface LocalContextOptions {
  readonly home?: string;
  readonly configPath?: string;
}

export type ComputeType = "standard" | "shared";

export interface RemoteContextOptions {
  readonly url?: string;
  readonly apiKey?: string;
  readonly requestTimeoutMs?: number;
  readonly userAgent?: string;
  readonly computeType?: ComputeType;
}

/** Shared destination configuration; no process-wide routing changes. */
export class Context {
  readonly sandboxes: Sandboxes;
  readonly volumes: Volumes;
  readonly snapshots: Snapshots;
  readonly checkpoints: Checkpoints;

  protected constructor(readonly native: NapiContext) {
    this.sandboxes = new Sandboxes(this);
    this.volumes = new Volumes(this);
    this.snapshots = new Snapshots(this);
    this.checkpoints = new Checkpoints(this);
  }

  /** @internal Rewrap already-retained native state without resolving configuration. */
  static fromNative(native: NapiContext): Context { return new Context(native); }
  get kind(): "local" | "remote" { return this.native.kind; }
  get info(): ContextInfo {
    try {
      const info = JSON.parse(this.native.infoJson) as { kind: "local" | "remote"; source: string; profile?: string; api_url?: string };
      return Object.freeze({ kind: info.kind, source: info.source, profile: info.profile, apiUrl: info.api_url });
    } catch (error) { throw mapNapiError(error); }
  }
}

export class LocalContext extends Context {
  constructor(options: LocalContextOptions = {}) {
    super(new (binding("local").Context)(JSON.stringify({ ...options, kind: "local" })));
  }
  static builder(): LocalContextBuilder { return new LocalContextBuilder(); }
}

export class RemoteContext extends Context {
  constructor(options: RemoteContextOptions | { readonly profile: string } = {}) {
    if ("requestTimeoutMs" in options && options.requestTimeoutMs !== undefined && (!Number.isSafeInteger(options.requestTimeoutMs) || options.requestTimeoutMs < 0)) {
      throw new RangeError("requestTimeoutMs must be a non-negative safe integer");
    }
    if (!("profile" in options)) {
      // Workers have their own process.env. Capture both fields before entering native code.
      const apiKey = options.apiKey ?? process.env.MSB_API_KEY;
      if (apiKey === undefined) throw new Error("RemoteContext requires apiKey or MSB_API_KEY");
      options = { ...options, apiKey, url: options.url ?? (process.env.MSB_API_URL?.trim() || "https://api.microsandbox.dev") };
    }
    super(new (binding("remote").Context)(JSON.stringify({ ...options, kind: "remote" })));
  }
  /** Construct a destination with an explicit endpoint, retaining transport options. */
  static withUrl(url: string, apiKey: string, options: Omit<RemoteContextOptions, "url" | "apiKey"> = {}): RemoteContext {
    return new RemoteContext({ ...options, url, apiKey });
  }
  static builder(): RemoteContextBuilder { return new RemoteContextBuilder(); }
  /** Derive from captured native state without rereading profiles or environment. */
  toBuilder(): RemoteContextBuilder { return new RemoteContextBuilder(this); }
  /** @internal Wrap a retained destination in its concrete type without reconstruction. */
  static override fromNative(native: NapiContext): RemoteContext {
    if (native.kind !== "remote") throw new TypeError("expected a remote context");
    return Object.setPrototypeOf(super.fromNative(native), RemoteContext.prototype) as RemoteContext;
  }
  static fromProfile(profile: string): RemoteContext {
    return new RemoteContext({ profile });
  }
  static fromEnv(): RemoteContext {
    return new RemoteContext();
  }
}

export class LocalContextBuilder {
  private options: LocalContextOptions = {};
  home(home: string): this { this.options = { ...this.options, home }; return this; }
  configPath(configPath: string): this { this.options = { ...this.options, configPath }; return this; }
  build(): LocalContext { return new LocalContext(this.options); }
}

export class RemoteContextBuilder {
  private options: Partial<RemoteContextOptions> = {};
  constructor(private readonly base?: RemoteContext) {}
  url(url: string): this { this.options = { ...this.options, url }; return this; }
  apiKey(apiKey: string): this { this.options = { ...this.options, apiKey }; return this; }
  requestTimeoutMs(requestTimeoutMs: number): this { this.options = { ...this.options, requestTimeoutMs }; return this; }
  computeType(computeType: ComputeType): this { this.options = { ...this.options, computeType }; return this; }
  userAgent(userAgent: string): this { this.options = { ...this.options, userAgent }; return this; }
  build(): RemoteContext {
    const timeout = this.options.requestTimeoutMs;
    if (timeout !== undefined && (!Number.isSafeInteger(timeout) || timeout < 0)) {
      throw new RangeError("requestTimeoutMs must be a non-negative safe integer");
    }
    if (this.base) {
      // Dispatch through the retained binding, even if provider registrations later change.
      return RemoteContext.fromNative(this.base.native.deriveRemote(JSON.stringify(this.options)));
    }
    return new RemoteContext(this.options);
  }
}

/** Factories retain this destination, including asynchronous creation and progress. */
export class Sandboxes {
  restore(snapshot: NapiSnapshotSeed): RestoreBuilder {
    const builder = typeof snapshot === "string"
      ? this.context.native.sandboxRestore(snapshot)
      : this.context.native.sandboxRestore(snapshot.reference, snapshot.referenceKind);
    return Sandbox.fromNativeRestoreBuilder(builder);
  }

  constructor(readonly context: Context) {}
  builder(name: string): SandboxBuilder {
    return Sandbox.fromNativeBuilder(name, this.context.native.sandboxBuilder(name));
  }
  async get(name: string): Promise<Sandbox> {
    return new Sandbox(await withMappedErrors(() => this.context.native.sandboxGet(name)), name);
  }
  async getRunning(name: string): Promise<Sandbox> {
    return new Sandbox(await withMappedErrors(() => this.context.native.sandboxGetRunning(name)), name);
  }
  async start(name: string): Promise<Sandbox> {
    return new Sandbox(await withMappedErrors(() => this.context.native.sandboxStart(name, false)), name);
  }
  async startDetached(name: string): Promise<Sandbox> {
    return new Sandbox(await withMappedErrors(() => this.context.native.sandboxStart(name, true)), name);
  }
  async list(): Promise<SandboxPage> {
    return sandboxPageFromNapi(await withMappedErrors(() => this.context.native.sandboxList()));
  }
  async listWith(configure: (list: SandboxListBuilder) => SandboxListBuilder): Promise<SandboxPage> {
    const options = configure(new SandboxListBuilder()).toNapi();
    return sandboxPageFromNapi(await withMappedErrors(() => this.context.native.sandboxList(options)));
  }
  async remove(name: string): Promise<void> {
    await withMappedErrors(() => this.context.native.sandboxRemove(name));
  }
}

export class Volumes {
  constructor(readonly context: Context) {}
  builder(name: string): VolumeBuilder {
    return Volume.fromNativeBuilder(this.context.native.volumeBuilder(name));
  }
  async get(name: string): Promise<Volume> {
    return new Volume(await withMappedErrors(() => this.context.native.volumeGet(name)));
  }
  async getDefault(): Promise<Volume> {
    return new Volume(await withMappedErrors(() => this.context.native.volumeGetDefault()));
  }
  async list(): Promise<Volume[]> {
    return (await withMappedErrors(() => this.context.native.volumeList())).map(value => new Volume(value));
  }
  async remove(name: string): Promise<void> {
    await withMappedErrors(() => this.context.native.volumeRemove(name));
  }
}

export class Snapshots {
  constructor(readonly context: Context) {}

  async open(path: string): Promise<Group> {
    return new Group(await withMappedErrors(() => this.context.native.snapshotGroupOpen(path)));
  }

  async load(name: string, files: string[], configure: (options: SnapshotLoadOptions) => SnapshotLoadOptions = options => options): Promise<SnapshotImportResult> {
    const options = configure(new SnapshotLoadOptions()).toNative();
    if (options.maximumDiskBytes != null && !nativeOwner(this.context.native)?.Snapshot.supportsImportBudget?.()) throw new UnsupportedError("Snapshot import size limits require an updated native SDK");
    return wrapImportResult(await withMappedErrors(() => this.context.native.snapshotGroupLoad(name, [...files], options)));
  }

  async get(name: string): Promise<Group> {
    return new Group(await withMappedErrors(() => this.context.native.snapshotGroupGet(name)));
  }

  async list(): Promise<Group[]> {
    return (await withMappedErrors(() => this.context.native.snapshotGroupList())).map(group => new Group(group));
  }
}

export class Checkpoints {
  async groupHead(group: string): Promise<string | null> {
    return (await withMappedErrors(() => this.context.native.snapshotGroupHead(group))) ?? null;
  }
  async setGroupHead(group: string, id: string): Promise<HeadUpdate> {
    const update = await withMappedErrors(() => this.context.native.snapshotSetGroupHead(group, id));
    return { ...update, previous: update.previous ?? null };
  }
  constructor(readonly context: Context) {}
  builder(name = ""): SnapshotBuilder { return wrapBuilder(this.context.native.snapshotBuilder(name)); }
  async get(reference: string): Promise<Snapshot> {
    return new Snapshot(await withMappedErrors(() => this.context.native.snapshotGet(reference)));
  }
  async list(): Promise<Snapshot[]> {
    return (await withMappedErrors(() => this.context.native.snapshotList())).map(value => new Snapshot(value));
  }
  async remove(reference: string, options: { force?: boolean } = {}): Promise<void> {
    await withMappedErrors(() => this.context.native.snapshotRemove(reference, options.force ?? false));
  }
}
