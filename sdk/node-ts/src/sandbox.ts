import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";
import type { NapiSandbox } from "./internal/napi.js";
import { ExecHandle, ExecOutput } from "./exec.js";
import { SandboxFs } from "./fs.js";
import {
  ExecOptionsBuilder,
  execOptionsToNapi,
} from "./exec-options-builder.js";
import {
  AttachOptionsBuilder,
  attachOptionsToNapi,
} from "./attach-options-builder.js";
import type { ExitStatus } from "./exit-status.js";
import { SandboxBuilder } from "./sandbox-builder.js";
import { SandboxHandle, sandboxInfoToHandle } from "./sandbox-handle.js";
import type { SandboxMetrics } from "./metrics.js";
import { metricsFromNapi } from "./internal/metrics.js";
import { MetricsStream } from "./metrics-stream.js";
import type { SandboxConfig } from "./sandbox-config.js";

export class Sandbox implements AsyncDisposable {
  /** @internal */
  readonly inner: NapiSandbox;
  readonly name: string;
  readonly config: Readonly<SandboxConfig>;
  readonly ownsLifecycle: boolean;

  /** @internal use `Sandbox.builder(name).create()` */
  constructor(
    inner: NapiSandbox,
    name: string,
    config: SandboxConfig,
    ownsLifecycle = true,
  ) {
    this.inner = inner;
    this.name = name;
    this.config = Object.freeze(config);
    this.ownsLifecycle = ownsLifecycle;
  }

  // -- statics ------------------------------------------------------------

  static builder(name: string): SandboxBuilder {
    return new SandboxBuilder(name);
  }

  /** Resume an existing stopped sandbox in attached mode. */
  static async start(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() => napi.Sandbox.start(name));
    return Sandbox.fromConnected(inner, name, /*ownsLifecycle*/ true);
  }

  /** Resume an existing stopped sandbox in detached mode. */
  static async startDetached(name: string): Promise<Sandbox> {
    const inner = await withMappedErrors(() =>
      napi.Sandbox.startDetached(name),
    );
    return Sandbox.fromConnected(inner, name, /*ownsLifecycle*/ false);
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

  private static async fromConnected(
    inner: NapiSandbox,
    name: string,
    ownsLifecycle: boolean,
  ): Promise<Sandbox> {
    // We don't have a `SandboxConfig` for a sandbox we didn't build —
    // expose a minimal placeholder. Calling `.config` returns this stub;
    // consumers wanting full config should round-trip through `Sandbox.get(name).config()`
    // when that returns the parsed shape.
    const placeholder: SandboxConfig = {
      name,
      image: { kind: "oci", reference: "" },
      cpus: null,
      memoryMib: null,
      logLevel: null,
      quietLogs: false,
      workdir: null,
      shell: null,
      entrypoint: null,
      cmd: null,
      hostname: null,
      user: null,
      libkrunfwPath: null,
      env: [],
      scripts: [],
      mounts: [],
      patches: [],
      pullPolicy: null,
      replace: false,
      maxDurationSecs: null,
      idleTimeoutSecs: null,
      portsTcp: [],
      portsUdp: [],
      registry: null,
      network: null,
      disableNetwork: false,
      secrets: [],
    };
    return new Sandbox(inner, name, placeholder, ownsLifecycle);
  }

  // -- exec ---------------------------------------------------------------

  async exec(cmd: string, args?: Iterable<string>): Promise<ExecOutput> {
    const argv = args ? Array.from(args) : undefined;
    const raw = await withMappedErrors(() => this.inner.exec(cmd, argv));
    return new ExecOutput(raw);
  }

  async execWith(
    cmd: string,
    configure: (b: ExecOptionsBuilder) => ExecOptionsBuilder,
  ): Promise<ExecOutput> {
    const opts = configure(new ExecOptionsBuilder()).build();
    const raw = await withMappedErrors(() =>
      this.inner.execWithConfig(execOptionsToNapi(cmd, opts)),
    );
    return new ExecOutput(raw);
  }

  async execStream(
    cmd: string,
    args?: Iterable<string>,
  ): Promise<ExecHandle> {
    const argv = args ? Array.from(args) : undefined;
    const raw = await withMappedErrors(() =>
      this.inner.execStream(cmd, argv),
    );
    return new ExecHandle(raw);
  }

  async execStreamWith(
    cmd: string,
    configure: (b: ExecOptionsBuilder) => ExecOptionsBuilder,
  ): Promise<ExecHandle> {
    const opts = configure(new ExecOptionsBuilder()).build();
    const raw = await withMappedErrors(() =>
      this.inner.execStreamWithConfig(execOptionsToNapi(cmd, opts)),
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
    configure: (b: AttachOptionsBuilder) => AttachOptionsBuilder,
  ): Promise<number> {
    const opts = configure(new AttachOptionsBuilder()).build();
    return await withMappedErrors(() =>
      this.inner.attachWithConfig(attachOptionsToNapi(cmd, opts)),
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
