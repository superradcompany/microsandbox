import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiAttachOptionsBuilder,
  type NapiExecOptionsBuilder,
  type NapiPullProgressCreate,
  type NapiPullProgressEvent,
  type NapiPullProgressStream,
  type NapiSandbox,
  type NapiSandboxBuilderSetters,
} from "./internal/napi.js";
import { ExecHandle, ExecOutput } from "./exec.js";
import { SandboxFs } from "./fs.js";
import type { ExitStatus } from "./exit-status.js";
import { SandboxHandle, sandboxInfoToHandle } from "./sandbox-handle.js";
import type { SandboxMetrics } from "./metrics.js";
import { metricsFromNapi } from "./internal/metrics.js";
import { MetricsStream } from "./metrics-stream.js";

/**
 * Fluent builder for a sandbox. Returned by `Sandbox.builder(name)`.
 *
 * The instance IS the napi-rs `SandboxBuilder` class — every setter is a
 * native call, no TS-side reimplementation. Only the terminal `create()`
 * / `createDetached()` methods are wrapped here so they return a TS
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
export interface SandboxBuilder extends NapiSandboxBuilderSetters {
  create(): Promise<Sandbox>;
  createDetached(): Promise<Sandbox>;
  createWithPullProgress(): Promise<PullProgressCreate>;
  createDetachedWithPullProgress(): Promise<PullProgressCreate>;
}

/**
 * Pair returned by `SandboxBuilder.createWithPullProgress()` —
 * the per-layer progress event stream plus a method to await the
 * final `Sandbox`.
 */
export class PullProgressCreate {
  /** @internal */
  private readonly inner: NapiPullProgressCreate;
  /** @internal */
  private readonly name: string;
  /** @internal */
  private readonly attached: boolean;

  /** @internal */
  constructor(inner: NapiPullProgressCreate, name: string, attached: boolean) {
    this.inner = inner;
    this.name = name;
    this.attached = attached;
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
    return new Sandbox(inner, this.name, this.attached);
  }
}

export class Sandbox implements AsyncDisposable {
  /** @internal */
  readonly inner: NapiSandbox;
  readonly name: string;
  readonly ownsLifecycle: boolean;

  /** @internal use `Sandbox.builder(name).create()` */
  constructor(inner: NapiSandbox, name: string, ownsLifecycle = true) {
    this.inner = inner;
    this.name = name;
    this.ownsLifecycle = ownsLifecycle;
  }

  // -- statics ------------------------------------------------------------

  /** Begin building a new sandbox. */
  static builder(name: string): SandboxBuilder {
    const nb = new napi.SandboxBuilder(name);
    const origCreate = nb.create.bind(nb);
    const origCreateDetached = nb.createDetached.bind(nb);
    const origCreateWithPP = nb.createWithPullProgress.bind(nb);
    const origCreateDetachedWithPP =
      nb.createDetachedWithPullProgress.bind(nb);
    // Override the terminals so they return a TS Sandbox.
    (nb as unknown as { create: () => Promise<Sandbox> }).create = async () => {
      const inner = await withMappedErrors(() => origCreate());
      return new Sandbox(inner, name, /*ownsLifecycle*/ true);
    };
    (
      nb as unknown as { createDetached: () => Promise<Sandbox> }
    ).createDetached = async () => {
      const inner = await withMappedErrors(() => origCreateDetached());
      return new Sandbox(inner, name, /*ownsLifecycle*/ false);
    };
    (
      nb as unknown as {
        createWithPullProgress: () => Promise<PullProgressCreate>;
      }
    ).createWithPullProgress = async () => {
      const raw = await withMappedErrors(() => origCreateWithPP());
      return new PullProgressCreate(raw, name, /*attached*/ true);
    };
    (
      nb as unknown as {
        createDetachedWithPullProgress: () => Promise<PullProgressCreate>;
      }
    ).createDetachedWithPullProgress = async () => {
      const raw = await withMappedErrors(() => origCreateDetachedWithPP());
      return new PullProgressCreate(raw, name, /*attached*/ false);
    };
    return nb as unknown as SandboxBuilder;
  }

  /** Resume an existing stopped sandbox in attached mode. */
  static async start(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() => napi.Sandbox.start(name));
    return new Sandbox(inner, name, /*ownsLifecycle*/ true);
  }

  /** Resume an existing stopped sandbox in detached mode. */
  static async startDetached(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() =>
      napi.Sandbox.startDetached(name),
    );
    return new Sandbox(inner, name, /*ownsLifecycle*/ false);
  }

  /** Look up a database handle for an existing sandbox. */
  static async get(name: string): Promise<SandboxHandle> {
    const h = await withMappedErrors(() => napi.Sandbox.get(name));
    return new SandboxHandle(h);
  }

  /** List all known sandboxes. */
  static async list(): Promise<SandboxHandle[]> {
    const infos = await withMappedErrors(() => napi.Sandbox.list());
    return infos.map(sandboxInfoToHandle);
  }

  /** Remove a stopped sandbox from the database. */
  static async remove(name: string): Promise<void> {
    await withMappedErrors(() => napi.Sandbox.remove(name));
  }

  // -- exec ---------------------------------------------------------------

  async exec(cmd: string, args?: Iterable<string>): Promise<ExecOutput> {
    const argv = args ? Array.from(args) : undefined;
    const raw = await withMappedErrors(() => this.inner.exec(cmd, argv));
    return new ExecOutput(raw);
  }

  async execWith(
    cmd: string,
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecOutput> {
    const builder = configure(new napi.ExecOptionsBuilder());
    const raw = await withMappedErrors(() =>
      this.inner.execWithBuilder(cmd, builder),
    );
    return new ExecOutput(raw);
  }

  async execStream(cmd: string, args?: Iterable<string>): Promise<ExecHandle> {
    const argv = args ? Array.from(args) : undefined;
    const raw = await withMappedErrors(() =>
      this.inner.execStream(cmd, argv),
    );
    return new ExecHandle(raw);
  }

  async execStreamWith(
    cmd: string,
    configure: (b: NapiExecOptionsBuilder) => NapiExecOptionsBuilder,
  ): Promise<ExecHandle> {
    const builder = configure(new napi.ExecOptionsBuilder());
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

  async attach(cmd: string, args?: Iterable<string>): Promise<number> {
    const argv = args ? Array.from(args) : undefined;
    return await withMappedErrors(() => this.inner.attach(cmd, argv));
  }

  async attachWith(
    cmd: string,
    configure: (b: NapiAttachOptionsBuilder) => NapiAttachOptionsBuilder,
  ): Promise<number> {
    const builder = configure(new napi.AttachOptionsBuilder());
    return await withMappedErrors(() =>
      this.inner.attachWithBuilder(cmd, builder),
    );
  }

  async attachShell(): Promise<number> {
    return await withMappedErrors(() => this.inner.attachShell());
  }

  // -- filesystem ---------------------------------------------------------

  fs(): SandboxFs {
    return new SandboxFs(this.inner.fs());
  }

  // -- config -------------------------------------------------------------

  /**
   * The full configuration this sandbox was created with — image, cpus,
   * memory, env, mounts, etc. The shape mirrors `SandboxBuilder.build()`.
   */
  async config(): Promise<unknown> {
    const json = await withMappedErrors(() => this.inner.configJson());
    return remapKeysToCamel(JSON.parse(json));
  }

  // -- metrics ------------------------------------------------------------

  async metrics(): Promise<SandboxMetrics> {
    const raw = await withMappedErrors(() => this.inner.metrics());
    return metricsFromNapi(raw);
  }

  /** Stream metrics snapshots at the given interval (in milliseconds). */
  async metricsStream(intervalMs: number): Promise<MetricsStream> {
    const raw = await withMappedErrors(() =>
      this.inner.metricsStream(intervalMs),
    );
    return new MetricsStream(raw);
  }

  // -- lifecycle ----------------------------------------------------------

  async stop(): Promise<void> {
    await withMappedErrors(() => this.inner.stop());
  }

  async stopAndWait(): Promise<ExitStatus> {
    return await withMappedErrors(() => this.inner.stopAndWait());
  }

  async kill(): Promise<void> {
    await withMappedErrors(() => this.inner.kill());
  }

  async drain(): Promise<void> {
    await withMappedErrors(() => this.inner.drain());
  }

  async wait(): Promise<ExitStatus> {
    return await withMappedErrors(() => this.inner.wait());
  }

  async detach(): Promise<void> {
    await withMappedErrors(() => this.inner.detach());
  }

  async removePersisted(): Promise<void> {
    await withMappedErrors(() => this.inner.removePersisted());
  }

  async [Symbol.asyncDispose](): Promise<void> {
    if (!this.ownsLifecycle) return;
    try {
      await this.inner.stop();
    } catch {
      // best-effort dispose
    }
  }
}

const snakeToCamel = (k: string): string =>
  k.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function remapKeysToCamel(v: any): any {
  if (Array.isArray(v)) return v.map(remapKeysToCamel);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) out[snakeToCamel(k)] = remapKeysToCamel(val);
    return out;
  }
  return v;
}
