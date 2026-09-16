import { ClientError, type ByteTransport, type ConnectContext, type Connector } from "@microsandbox/protocol-client";
import { ControlClientError } from "./error.js";

/** An absolute control-operation scope, including dial, verification, and I/O. */
export class ControlAttempt {
  readonly #controller = new AbortController();
  readonly #cleanup: Array<() => void> = [];
  readonly deadlineMs: number;
  get signal(): AbortSignal { return this.#controller.signal; }
  get context(): ConnectContext { return { deadlineMs: this.deadlineMs, signal: this.signal }; }

  constructor(timeoutMs: number, signals: readonly (AbortSignal | undefined)[] = []) {
    validateTimeout(timeoutMs);
    this.deadlineMs = performance.now() + timeoutMs;
    for (const signal of signals) {
      if (!signal) continue;
      const abort = () => this.#controller.abort(signal.reason instanceof ClientError ? signal.reason : new ClientError("cancelled"));
      if (signal.aborted) abort();
      else { signal.addEventListener("abort", abort, { once: true }); this.#cleanup.push(() => signal.removeEventListener("abort", abort)); }
    }
    if (timeoutMs === 0) this.#controller.abort(new ClientError("timeout"));
    else {
      const timer = setTimeout(() => this.#controller.abort(new ClientError("timeout")), timeoutMs);
      this.#cleanup.push(() => clearTimeout(timer));
    }
  }

  check(): void {
    if (performance.now() >= this.deadlineMs && !this.signal.aborted) this.#controller.abort(new ClientError("timeout"));
    if (this.signal.aborted) throw this.signal.reason;
  }
  remaining(): number { this.check(); return Math.max(0, this.deadlineMs - performance.now()); }
  async run<T>(work: () => Promise<T>): Promise<T> {
    this.check();
    return new Promise<T>((resolve, reject) => {
      const abort = () => reject(this.signal.reason);
      this.signal.addEventListener("abort", abort, { once: true });
      Promise.resolve().then(() => { this.check(); return work(); }).then(resolve, reject)
        .finally(() => this.signal.removeEventListener("abort", abort));
      if (this.signal.aborted) abort();
    });
  }
  async connect(connector: Connector): Promise<ByteTransport> {
    return this.run(() => connector.connect(this.context).then(transport => {
      // Even a connector that ignores cancellation transfers ownership. Close
      // its late result instead of leaving an unobserved live socket behind.
      try { this.check(); } catch (error) { void closeTransport(transport); throw error; }
      return transport;
    }));
  }
  dispose(): void { for (const cleanup of this.#cleanup.splice(0)) cleanup(); }
}

export function validateTimeout(value: number): void {
  if (!Number.isFinite(value) || value < 0 || value > 0x7fffffff) throw new ClientError("invalid_options");
}
export function controlError(error: unknown): ClientError | ControlClientError {
  return error instanceof ClientError || error instanceof ControlClientError ? error : new ClientError("io");
}
export async function closeTransport(transport: ByteTransport): Promise<void> {
  try { await transport.close(); } catch { /* Preserve the exchange's original outcome. */ }
}
