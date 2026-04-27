import { withMappedErrors } from "./internal/error-mapping.js";
import { mapAsyncIterable } from "./internal/async-iter.js";
import type {
  NapiExecHandle,
  NapiExecOutput,
  NapiExecSink,
  NapiExitStatus,
} from "./internal/napi.js";
import { normalizeExecEvent } from "./exec-event.js";
import type { ExecEvent } from "./exec-event.js";
import type { ExitStatus } from "./exit-status.js";

export class ExecOutput {
  private readonly inner: NapiExecOutput;

  /** @internal */
  constructor(inner: NapiExecOutput) {
    this.inner = inner;
  }

  get code(): number {
    return this.inner.code;
  }

  get success(): boolean {
    return this.inner.success;
  }

  get status(): ExitStatus {
    return { code: this.inner.code, success: this.inner.success };
  }

  /** Decode stdout as UTF-8. Lossy on invalid sequences. */
  stdout(): string {
    return this.inner.stdout();
  }

  /** Decode stderr as UTF-8. Lossy on invalid sequences. */
  stderr(): string {
    return this.inner.stderr();
  }

  /** Raw stdout bytes. */
  stdoutBytes(): Uint8Array {
    return new Uint8Array(this.inner.stdoutBytes());
  }

  /** Raw stderr bytes. */
  stderrBytes(): Uint8Array {
    return new Uint8Array(this.inner.stderrBytes());
  }
}

export class ExecSink implements AsyncDisposable {
  private readonly inner: NapiExecSink;
  private closed = false;

  /** @internal */
  constructor(inner: NapiExecSink) {
    this.inner = inner;
  }

  /** Write data to the process's stdin. */
  async write(data: Uint8Array | string): Promise<void> {
    const buf =
      typeof data === "string"
        ? Buffer.from(data, "utf8")
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    await withMappedErrors(() => this.inner.write(buf));
  }

  /** Send EOF. Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await withMappedErrors(() => this.inner.close());
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

export class ExecHandle implements AsyncIterable<ExecEvent>, AsyncDisposable {
  private readonly inner: NapiExecHandle;
  private stdinTaken = false;

  /** @internal */
  constructor(inner: NapiExecHandle) {
    this.inner = inner;
  }

  /** Receive the next event, or `null` once the stream ends. */
  async recv(): Promise<ExecEvent | null> {
    const raw = await withMappedErrors(() => this.inner.recv());
    return raw === null ? null : normalizeExecEvent(raw);
  }

  /** Take ownership of the stdin sink. Returns `null` after the first call. */
  async takeStdin(): Promise<ExecSink | null> {
    if (this.stdinTaken) return null;
    const raw = await withMappedErrors(() => this.inner.takeStdin());
    if (raw === null) return null;
    this.stdinTaken = true;
    return new ExecSink(raw);
  }

  /** Wait for the process to exit. */
  async wait(): Promise<ExitStatus> {
    return await withMappedErrors(() => this.inner.wait());
  }

  /** Drain stdout/stderr and wait for exit. */
  async collect(): Promise<ExecOutput> {
    const raw = await withMappedErrors(() => this.inner.collect());
    return new ExecOutput(raw);
  }

  async signal(signal: number): Promise<void> {
    await withMappedErrors(() => this.inner.signal(signal));
  }

  async kill(): Promise<void> {
    await withMappedErrors(() => this.inner.kill());
  }

  [Symbol.asyncIterator](): AsyncIterator<ExecEvent> {
    return mapAsyncIterable(this.inner, normalizeExecEvent)[Symbol.asyncIterator]();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await withMappedErrors(() => this.inner.kill()).catch(() => undefined);
  }
}

/** Internal — exposed in `internal/napi-types.ts` shape. */
export function exitStatusFromNapi(s: NapiExitStatus): ExitStatus {
  return { code: s.code, success: s.success };
}
