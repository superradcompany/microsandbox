import { withMappedErrors } from "./internal/error-mapping.js";
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

  async *[Symbol.asyncIterator](): AsyncIterator<SandboxMetrics> {
    for (;;) {
      const metrics = await this.recv();
      if (metrics === null) return;
      yield metrics;
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.done = true;
  }
}
