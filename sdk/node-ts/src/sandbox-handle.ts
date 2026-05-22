import { withMappedErrors } from "./internal/error-mapping.js";
import { metricsFromNapi } from "./internal/metrics.js";
import type {
  NapiSandboxHandle,
  NapiSandboxInfo,
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
import { Sandbox } from "./sandbox.js";
import type { SandboxStatus } from "./sandbox-status.js";
import type { SandboxMetrics } from "./metrics.js";
import { Snapshot } from "./snapshot.js";

const READ_ONLY_MSG =
  "SandboxHandle is read-only — fetch a live handle via Sandbox.get(name) for lifecycle methods.";

export class SandboxHandle {
  private readonly inner: NapiSandboxHandle | NapiSandboxInfo;
  readonly name: string;
  readonly status: SandboxStatus;
  readonly configJson: string;
  readonly createdAt: Date | null;
  readonly updatedAt: Date | null;

  /** @internal */
  constructor(inner: NapiSandboxHandle | NapiSandboxInfo) {
    this.inner = inner;
    this.name = inner.name;
    this.status = inner.status as SandboxStatus;
    this.configJson = inner.configJson;
    this.createdAt =
      typeof inner.createdAt === "number" ? new Date(inner.createdAt) : null;
    this.updatedAt =
      typeof inner.updatedAt === "number" ? new Date(inner.updatedAt) : null;
  }

  private requireLive(): NapiSandboxHandle {
    if (!isHandle(this.inner)) throw new Error(READ_ONLY_MSG);
    return this.inner;
  }

  /** Get point-in-time metrics. */
  async metrics(): Promise<SandboxMetrics> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.metrics());
    return metricsFromNapi(raw);
  }

  /** Resume in attached mode. */
  async start(): Promise<Sandbox> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.start());
    return new Sandbox(raw, this.name, true);
  }

  /** Resume in detached mode. */
  async startDetached(): Promise<Sandbox> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.startDetached());
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Connect to an already-running sandbox without taking lifecycle
   * ownership. Returns an error if the sandbox doesn't respond within
   * 10_000 ms; use `connectWithTimeout` to override.
   */
  async connect(): Promise<Sandbox> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.connect());
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Connect with an explicit timeout in milliseconds. Returns an error
   * if the sandbox doesn't respond in this window.
   */
  async connectWithTimeout(timeoutMs: number): Promise<Sandbox> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.connectWithTimeout(timeoutMs));
    return new Sandbox(raw, this.name, false);
  }

  /**
   * Gracefully shut down the sandbox. Lets it finish writing any
   * pending data to disk before it exits, so files written inside the
   * sandbox aren't lost across a later restart. Force-kills after
   * 10_000 ms by default; use `stopWithTimeout` to override.
   */
  async stop(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.stop());
  }

  /**
   * Stop gracefully with an explicit timeout in milliseconds. If the
   * sandbox is still running after this window, it is force-killed.
   * `0` force-kills immediately. Resolves successfully either way —
   * does not throw on timeout expiry.
   */
  async stopWithTimeout(timeoutMs: number): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.stopWithTimeout(timeoutMs));
  }

  async kill(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.kill());
  }

  async remove(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.remove());
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
    const live = this.requireLive();
    const napiOpts = logReadOptionsToNapi(opts);
    const raw = await withMappedErrors(() => live.logs(napiOpts));
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
    const live = this.requireLive();
    const napiOpts = logStreamOptionsToNapi(opts);
    const raw = await withMappedErrors(() => live.logStream(napiOpts));
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
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.snapshot(name));
    return new Snapshot(raw);
  }

  /** Snapshot this (stopped) sandbox to an explicit filesystem path. */
  async snapshotTo(path: string): Promise<Snapshot> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.snapshotTo(path));
    return new Snapshot(raw);
  }
}

function isHandle(
  v: NapiSandboxHandle | NapiSandboxInfo,
): v is NapiSandboxHandle {
  return typeof (v as { start?: unknown }).start === "function";
}

/** @internal */
export function sandboxInfoToHandle(info: NapiSandboxInfo): SandboxHandle {
  return new SandboxHandle(info);
}
