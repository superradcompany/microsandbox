import { binding } from "./internal/provider.js";
import { type NapiSnapshotSeed, type NapiContext } from "./internal/napi.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import { Sandbox, SandboxListBuilder, sandboxPageFromNapi, type RestoreBuilder, type SandboxBuilder, type SandboxPage } from "./sandbox.js";
import { Volume, type VolumeBuilder } from "./volume.js";
import { Snapshot, wrapBuilder, type SnapshotBuilder } from "./snapshot.js";

export interface LocalContextOptions {
  readonly home?: string;
  readonly configPath?: string;
}

export interface RemoteContextOptions {
  readonly url?: string;
  readonly apiKey: string;
  readonly requestTimeoutMs?: number;
  readonly userAgent?: string;
}

/** Shared destination configuration; no process-wide routing changes. */
export class Context {
  readonly sandboxes: Sandboxes;
  readonly volumes: Volumes;
  readonly snapshots: Snapshots;

  protected constructor(readonly native: NapiContext) {
    this.sandboxes = new Sandboxes(this);
    this.volumes = new Volumes(this);
    this.snapshots = new Snapshots(this);
  }

  /** @internal Rewrap already-retained native state without resolving configuration. */
  static fromNative(native: NapiContext): Context { return new Context(native); }
  get kind(): "local" | "remote" { return this.native.kind; }
}

export class LocalContext extends Context {
  constructor(options: LocalContextOptions = {}) {
    super(new (binding("local").Context)(JSON.stringify({ ...options, kind: "local" })));
  }
  static builder(): LocalContextBuilder { return new LocalContextBuilder(); }
}

export class RemoteContext extends Context {
  constructor(options: RemoteContextOptions | { readonly profile: string }) {
    if ("requestTimeoutMs" in options && options.requestTimeoutMs !== undefined && (!Number.isSafeInteger(options.requestTimeoutMs) || options.requestTimeoutMs < 0)) {
      throw new RangeError("requestTimeoutMs must be a non-negative safe integer");
    }
    super(new (binding("remote").Context)(JSON.stringify({ ...options, kind: "remote" })));
  }
  /** Construct a destination with an explicit endpoint, retaining transport options. */
  static withUrl(url: string, apiKey: string, options: Omit<RemoteContextOptions, "url" | "apiKey"> = {}): RemoteContext {
    return new RemoteContext({ ...options, url, apiKey });
  }
  static builder(): RemoteContextBuilder { return new RemoteContextBuilder(); }
  static fromProfile(profile: string): RemoteContext {
    return new RemoteContext({ profile });
  }
  static fromEnv(): RemoteContext {
    const apiKey = process.env.MSB_API_KEY;
    if (!apiKey) throw new Error("MSB_API_KEY is required for RemoteContext.fromEnv()");
    return new RemoteContext({ apiKey, url: process.env.MSB_API_URL });
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
  url(url: string): this { this.options = { ...this.options, url }; return this; }
  apiKey(apiKey: string): this { this.options = { ...this.options, apiKey }; return this; }
  requestTimeoutMs(requestTimeoutMs: number): this { this.options = { ...this.options, requestTimeoutMs }; return this; }
  userAgent(userAgent: string): this { this.options = { ...this.options, userAgent }; return this; }
  build(): RemoteContext {
    const apiKey = this.options.apiKey;
    if (apiKey === undefined) throw new Error("remote context requires apiKey");
    return new RemoteContext({ ...this.options, apiKey });
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
