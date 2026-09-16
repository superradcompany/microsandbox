import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import { validateStopTimeout } from "./internal/stop.js";
import {
  compactionResultFromJson,
  type DiskCompactionOptions,
  type DiskCompactionResult,
} from "./compact.js";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
  type ModifyOptions,
  type SandboxModificationPlan,
} from "./modify.js";
import { metricsFromNapi } from "./internal/metrics.js";
import type {
  NapiSandboxConfig,
  NapiSandboxDestroyOptions,
  NapiSandboxHandle,
  NapiSandboxRestartOptions,
} from "./internal/napi.js";
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
  Sandbox,
  type SandboxPingResult,
  type SandboxTouchResult,
} from "./sandbox.js";
import type { SandboxStatus } from "./sandbox-status.js";
import type { SandboxMetrics } from "./metrics.js";
import { Snapshot } from "./snapshot.js";

export interface SandboxStopResult {
  readonly name: string;
  readonly status: SandboxStatus;
  readonly exitCode: number | null;
  readonly signal: number | null;
  readonly observedAt: Date;
  readonly source: string | null;
}

export type RestartOptions = NapiSandboxRestartOptions;
export type DestroyOptions = NapiSandboxDestroyOptions;

export class SandboxHandle {
  private readonly inner: NapiSandboxHandle;
  /** Sandbox name. Names are limited to 128 UTF-8 bytes. */
  readonly name: string;
  /** Stable identity that changes when this name is removed and recreated. */
  readonly id: string;
  readonly status: SandboxStatus;
  /** Backend retained by this handle. */
  readonly backendKind: "local" | "cloud";
  readonly configJson: string;
  readonly createdAt: Date | null;
  readonly updatedAt: Date | null;

  /** @internal */
  constructor(inner: NapiSandboxHandle) {
    this.inner = inner;
    this.name = inner.name;
    this.id = inner.id;
    this.status = inner.status as SandboxStatus;
    this.backendKind = inner.backendKind;
    this.configJson = inner.configJson;
    this.createdAt =
      typeof inner.createdAt === "number" ? new Date(inner.createdAt) : null;
    this.updatedAt =
      typeof inner.updatedAt === "number" ? new Date(inner.updatedAt) : null;
  }

  config(): NapiSandboxConfig {
    return remapKeysToCamel(JSON.parse(this.configJson)) as NapiSandboxConfig;
  }

  async refresh(): Promise<SandboxHandle> {
    const raw = await withMappedErrors(() => this.inner.refresh());
    return new SandboxHandle(raw);
  }

  /** Get point-in-time metrics. */
  async metrics(): Promise<SandboxMetrics> {
    const raw = await withMappedErrors(() => this.inner.metrics());
    return metricsFromNapi(raw);
  }

  /**
   * Check whether agentd is reachable without refreshing idle activity.
   *
   * This connects to an already-running sandbox and does not start stopped
   * sandboxes implicitly.
   */
  async ping(): Promise<SandboxPingResult> {
    return await withMappedErrors(() => this.inner.ping());
  }

  /**
   * Explicitly refresh this sandbox's idle activity timer.
   *
   * This connects to an already-running sandbox and does not start stopped
   * sandboxes implicitly.
   */
  async touch(): Promise<SandboxTouchResult> {
    return await withMappedErrors(() => this.inner.touch());
  }

  /**
   * Plan or apply a sandbox modification. With `dryRun: true` the plan is
   * computed without applying anything.
   */
  async modify(opts?: ModifyOptions): Promise<SandboxModificationPlan> {
    const raw = await withMappedErrors(() =>
      this.inner.modify(modifyOptionsToNapi(opts)),
    );
    return modificationPlanFromJson(raw);
  }

  /** Compact sealed root and owned-data disk layers, running or stopped. */
  async compact(opts?: DiskCompactionOptions): Promise<DiskCompactionResult> {
    const raw = await withMappedErrors(() =>
      this.inner.compact(opts?.layers, opts?.dryRun, opts?.disk, opts?.rootDiskOnly),
    );
    return compactionResultFromJson(raw);
  }

  /** Resume in attached mode. */
  async start(): Promise<Sandbox> {
    const raw = await withMappedErrors(() => this.inner.start());
    return new Sandbox(raw, this.name, true);
  }

  /** Resume in detached mode. */
  async startDetached(): Promise<Sandbox> {
    const raw = await withMappedErrors(() => this.inner.startDetached());
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Connect to an already-running sandbox without taking lifecycle
   * ownership. Returns an error if the sandbox doesn't respond within
   * 10_000 ms; use `connectWithTimeout` to override.
   */
  async connect(): Promise<Sandbox> {
    const raw = await withMappedErrors(() => this.inner.connect());
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Connect with an explicit timeout in milliseconds. Returns an error
   * if the sandbox doesn't respond in this window.
   */
  async connectWithTimeout(timeoutMs: number): Promise<Sandbox> {
    const raw = await withMappedErrors(() =>
      this.inner.connectWithTimeout(timeoutMs),
    );
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Connect when this exact sandbox is running, wait while it is starting, or
   * start it when it is created, stopped, or crashed.
   *
   * `detached` applies only when a start is required. A same-name replacement
   * is rejected instead of becoming the target of this handle.
   */
  async connectOrStart(options?: { detached?: boolean }): Promise<Sandbox> {
    const detached = options?.detached ?? false;
    const raw = await withMappedErrors(() =>
      this.inner.connectOrStart(detached),
    );
    // Connecting to an existing running sandbox never takes lifecycle
    // ownership; only a start can return an owning attached handle.
    return new Sandbox(raw, this.name);
  }

  /**
   * Wait indefinitely for graceful shutdown and release of the targeted runtime's
   * ownership. No implicit kill; use `stopWithTimeout` for a bounded wait.
   */
  async stop(): Promise<void> {
    await withMappedErrors(() => this.inner.stop());
  }

  /** Create an independent local CoW child without a durable full snapshot. */
  async branch(name: string, options: { recordIntegrity?: boolean; guestFlush?: import("./snapshot.js").GuestFlush } = {}): Promise<Sandbox> {
    const child = await withMappedErrors(() => this.inner.branch(name, options.recordIntegrity, options.guestFlush));
    return new Sandbox(child, name, false);
  }

  /** Capture once; return each named child's startup outcome in input order. */
  async branchMany(names: string[], options: { recordIntegrity?: boolean; guestFlush?: import("./snapshot.js").GuestFlush } = {}): Promise<import("./sandbox.js").BranchOutcome[]> {
    const outcomes = await withMappedErrors(() => this.inner.branchMany(names, options.recordIntegrity, options.guestFlush));
    return outcomes.map(o => o.sandbox
      ? { name: o.name, sandbox: new Sandbox(o.sandbox, o.name, false) }
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

  /**
   * One graceful-completion budget in milliseconds. Expiry throws StopTimeoutError
   * without killing. Zero expires before dispatch; a delivered request may finish later.
   */
  async stopWithTimeout(timeoutMs: number): Promise<void> {
    validateStopTimeout(timeoutMs);
    await withMappedErrors(() => this.inner.stopWithTimeout(timeoutMs));
  }

  async kill(): Promise<void> {
    await withMappedErrors(() => this.inner.kill());
  }

  async requestKill(): Promise<void> {
    await withMappedErrors(() => this.inner.requestKill());
  }

  async killWithTimeout(timeoutMs: number): Promise<void> {
    await withMappedErrors(() => this.inner.killWithTimeout(timeoutMs));
  }

  async requestDrain(): Promise<void> {
    await withMappedErrors(() => this.inner.requestDrain());
  }

  /**
   * Wait until this exact persisted sandbox reaches `status`.
   * This method has no built-in timeout and rejects same-name replacements.
   */
  async waitForStatus(status: SandboxStatus): Promise<SandboxHandle> {
    const raw = await withMappedErrors(() => this.inner.waitForStatus(status));
    return new SandboxHandle(raw);
  }

  /**
   * Stop and start this exact persisted sandbox.
   * Graceful shutdown and a ten-second convergence timeout are the defaults.
   */
  async restart(options?: RestartOptions): Promise<Sandbox> {
    const raw = await withMappedErrors(() => this.inner.restart(options));
    return new Sandbox(raw, this.name);
  }

  /**
   * Stop and remove this exact persisted sandbox.
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

  async remove(): Promise<void> {
    await withMappedErrors(() => this.inner.remove());
  }

  /**
   * Read captured output from `exec.log` for this sandbox.
   *
   * Works without starting the sandbox. Defaults to user output:
   * `stdout`, `stderr`, and pty-merged `output`. Pass
   * `{ sources: ["system"] }` for runtime/kernel diagnostics or
   * `{ sources: ["all"] }` for everything.
   */
  async logs(opts?: LogReadOptions): Promise<LogEntry[]> {
    const napiOpts = logReadOptionsToNapi(opts);
    const raw = await withMappedErrors(() => this.inner.logs(napiOpts));
    return raw.map(logEntryFromNapi);
  }

  /**
   * Stream captured output as it appears, with optional follow.
   *
   * Works without starting the sandbox; with `{ follow: true }`,
   * the stream picks up new entries the moment they land in
   * `exec.log`.
   */
  async logStream(opts?: LogStreamOptions): Promise<LogStream> {
    const napiOpts = logStreamOptionsToNapi(opts);
    const raw = await withMappedErrors(() => this.inner.logStream(napiOpts));
    return new LogStream(raw);
  }

  /**
   * Snapshot this sandbox's disk under a bare name. Resolves under
   * `~/.microsandbox/snapshots/<name>/`. For an explicit filesystem
   * destination, move the artifact with `Snapshot.save`/`Snapshot.load`.
   *
   * Live sources use automatic guest writeback. A paused source needs a matching
   * prior flush and is never resumed implicitly. Use Snapshot.builder to select
   * another guestFlush policy.
   */
  async snapshot(name: string): Promise<Snapshot> {
    const raw = await withMappedErrors(() => this.inner.snapshot(name));
    return new Snapshot(raw);
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
    status: result.status as SandboxStatus,
    exitCode: result.exitCode ?? null,
    signal: result.signal ?? null,
    observedAt: new Date(result.observedAt),
    source: result.source ?? null,
  };
}

function remapKeysToCamel(v: any): any {
  if (Array.isArray(v)) return v.map(remapKeysToCamel);
  if (v && typeof v === "object" && v.constructor === Object) {
    const out: any = {};
    for (const [k, val] of Object.entries(v)) out[snakeToCamel(k)] = remapKeysToCamel(val);
    return out;
  }
  return v;
}

function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
}
