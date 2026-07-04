import { withMappedErrors } from "./internal/error-mapping.js";
import {
  modificationPlanFromJson,
  modifyOptionsToNapi,
  type ModifyOptions,
  type SandboxModificationPlan,
} from "./modify.js";
import { metricsFromNapi } from "./internal/metrics.js";
import type { NapiSandboxConfig, NapiSandboxHandle } from "./internal/napi.js";
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

export class SandboxHandle {
  private readonly inner: NapiSandboxHandle;
  /** Sandbox name. Names are limited to 128 UTF-8 bytes. */
  readonly name: string;
  readonly status: SandboxStatus;
  readonly configJson: string;
  readonly createdAt: Date | null;
  readonly updatedAt: Date | null;

  /** @internal */
  constructor(inner: NapiSandboxHandle) {
    this.inner = inner;
    this.name = inner.name;
    this.status = inner.status as SandboxStatus;
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
   * Gracefully shut down the sandbox. Lets it finish writing any
   * pending data to disk before it exits, so files written inside the
   * sandbox aren't lost across a later restart. Force-kills after
   * 10_000 ms by default; use `stopWithTimeout` to override.
   */
  async stop(): Promise<void> {
    await withMappedErrors(() => this.inner.stop());
  }

  async requestStop(): Promise<void> {
    await withMappedErrors(() => this.inner.requestStop());
  }

  /**
   * Stop gracefully with an explicit timeout in milliseconds. If the
   * sandbox is still running after this window, it is force-killed.
   * `0` force-kills immediately. Resolves successfully either way —
   * does not throw on timeout expiry.
   */
  async stopWithTimeout(timeoutMs: number): Promise<void> {
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
   * Snapshot this (stopped) sandbox under a bare name. Resolves under
   * `~/.microsandbox/snapshots/<name>/`. For an explicit filesystem
   * destination, see `snapshotTo`.
   *
   * The sandbox must be stopped (or crashed); running sandboxes are
   * rejected with a `SnapshotSandboxRunning` error.
   */
  async snapshot(name: string): Promise<Snapshot> {
    const raw = await withMappedErrors(() => this.inner.snapshot(name));
    return new Snapshot(raw);
  }

  /** Snapshot this (stopped) sandbox to an explicit filesystem path. */
  async snapshotTo(path: string): Promise<Snapshot> {
    const raw = await withMappedErrors(() => this.inner.snapshotTo(path));
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
