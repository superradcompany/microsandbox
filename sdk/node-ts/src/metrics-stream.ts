import { withMappedErrors } from "./internal/error-mapping.js";
import { mapAsyncIterable } from "./internal/async-iter.js";
import { metricsFromNapi } from "./internal/metrics.js";
import type { NapiMetricsStream } from "./internal/napi.js";
import type { SandboxMetrics } from "./metrics.js";

export class MetricsStream
  implements AsyncIterable<SandboxMetrics>, AsyncDisposable
{
  private readonly inner: NapiMetricsStream;
  private done = false;

  /** @internal */
  constructor(inner: NapiMetricsStream) {
    this.inner = inner;
  }

  async recv(): Promise<SandboxMetrics | null> {
    if (this.done) return null;
    const raw = await withMappedErrors(() => this.inner.recv());
    if (raw === null) {
      this.done = true;
      return null;
    }
    return metricsFromNapi(raw);
  }

  [Symbol.asyncIterator](): AsyncIterator<SandboxMetrics> {
    return mapAsyncIterable(
      { recv: () => this.inner.recv() },
      metricsFromNapi,
    )[Symbol.asyncIterator]();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.done = true;
  }
}
