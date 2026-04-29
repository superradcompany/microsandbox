import { withMappedErrors } from "./internal/error-mapping.js";
import { metricsFromNapi } from "./internal/metrics.js";
import type {
  NapiSandboxHandle,
  NapiSandboxInfo,
} from "./internal/napi.js";
import { Sandbox } from "./sandbox.js";
import type { SandboxStatus } from "./sandbox-status.js";
import type { SandboxMetrics } from "./metrics.js";

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

  /** Connect to an already-running sandbox without taking lifecycle ownership. */
  async connect(): Promise<Sandbox> {
    const live = this.requireLive();
    const raw = await withMappedErrors(() => live.connect());
    return new Sandbox(raw, this.name, false);
  }

  async stop(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.stop());
  }

  async kill(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.kill());
  }

  async remove(): Promise<void> {
    const live = this.requireLive();
    await withMappedErrors(() => live.remove());
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
