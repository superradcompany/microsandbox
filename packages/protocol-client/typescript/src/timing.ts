import { ClientError } from "./error.js";

/** One deadline/cancellation scope, disposed after the entire attempt. */
export class Attempt {
  readonly signal: AbortSignal;
  private readonly controller = new AbortController();
  private timer?: ReturnType<typeof setTimeout>;
  private readonly forward = () => this.controller.abort(new ClientError("cancelled"));

  constructor(timeoutMs?: number, private readonly parent?: AbortSignal) {
    this.signal = this.controller.signal;
    if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > 0x7fffffff)) throw new ClientError("invalid_options");
    if (parent?.aborted) this.forward();
    else parent?.addEventListener("abort", this.forward, { once: true });
    if (timeoutMs !== undefined) this.timer = setTimeout(() => this.controller.abort(new ClientError("timeout")), timeoutMs);
  }

  close(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.parent?.removeEventListener("abort", this.forward);
  }
}

export function checkSignal(signal?: AbortSignal): void {
  if (signal?.aborted) throw signalError(signal);
}

export function signalError(signal: AbortSignal): ClientError {
  return signal.reason instanceof ClientError ? signal.reason : new ClientError("cancelled");
}

/** Stop local waiting; callers choose whether the underlying work can be cancelled. */
export function wait<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return work;
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signalError(signal));
    signal.addEventListener("abort", abort, { once: true });
    // Attach both handlers even for pre-aborted signals: underlying failures
    // must not become unhandled rejections after local waiting has stopped.
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}
