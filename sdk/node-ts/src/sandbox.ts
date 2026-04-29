import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiAttachOptionsBuilder,
  type NapiExecOptionsBuilder,
  type NapiSandbox,
  type NapiSandboxBuilder,
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
export type SandboxBuilder = Omit<
  NapiSandboxBuilder,
  "create" | "createDetached"
> & {
  create(): Promise<Sandbox>;
  createDetached(): Promise<Sandbox>;
};

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
