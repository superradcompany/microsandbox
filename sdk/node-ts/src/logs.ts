import { withMappedErrors } from "./internal/error-mapping.js";
import { mapAsyncIterable } from "./internal/async-iter.js";
import type {
  LogEntry as NapiLogEntry,
  LogOptions as NapiLogOptions,
  LogStreamOptions as NapiLogStreamOptions,
  NapiLogStream,
} from "./internal/napi.js";

/**
 * Source tag on a captured log entry.
 *
 * - `"stdout"` / `"stderr"` — the primary exec session's output in
 *   pipe mode, where the streams remain separated end to end.
 * - `"output"` — the primary exec session's merged stream when
 *   running in pty mode (pty allocation collapses stdout+stderr into
 *   a single stream at the kernel level inside the guest).
 * - `"system"` — synthetic lifecycle markers and runtime/kernel
 *   diagnostics (only emitted when explicitly requested via the
 *   `sources` option).
 */
export type LogSource = "stdout" | "stderr" | "output" | "system";

/**
 * Source filter accepted by {@link Sandbox.logs}.
 *
 * `"all"` is a convenience alias for every log source. Returned
 * entries still use concrete {@link LogSource} values.
 */
export type LogReadSource = LogSource | "all";

/**
 * One captured log entry from `exec.log`.
 *
 * Bytes are exposed via `data` as a `Uint8Array`. Use `text()` for a
 * UTF-8-lossy decode.
 */
export class LogEntry {
  /** Wall-clock capture time on the host. */
  readonly timestamp: Date;

  /** `"stdout"`, `"stderr"`, `"output"`, or `"system"`. */
  readonly source: LogSource;

  /**
   * Exec session correlation id. `null` for `system` lifecycle
   * markers, which aren't tied to a specific session. Useful when
   * grouping entries by session: `entries.filter(e => e.sessionId
   * === 42)`.
   */
  readonly sessionId: number | null;

  /** The captured chunk's bytes. */
  readonly data: Uint8Array;

  /**
   * Opaque resume token. Pass back to {@link Sandbox.logStream} as
   * {@link LogStreamOptions.fromCursor} to resume the stream
   * immediately after this entry.
   */
  readonly cursor: string;

  constructor(
    timestamp: Date,
    source: LogSource,
    sessionId: number | null,
    data: Uint8Array,
    cursor: string,
  ) {
    this.timestamp = timestamp;
    this.source = source;
    this.sessionId = sessionId;
    this.data = data;
    this.cursor = cursor;
  }

  /** UTF-8 decode of {@link data} (lossy — invalid bytes are replaced). */
  text(): string {
    return new TextDecoder("utf-8", { fatal: false }).decode(this.data);
  }
}

/**
 * Options for {@link Sandbox.logs}.
 *
 * All fields optional. Defaults: every entry, sources = `stdout +
 * stderr + output`.
 */
export interface LogReadOptions {
  /** Show only the last N entries after other filters apply. */
  tail?: number;

  /** Inclusive lower bound on entry timestamp. */
  since?: Date;

  /** Exclusive upper bound on entry timestamp. */
  until?: Date;

  /**
   * Sources to include. Defaults to `["stdout", "stderr", "output"]`
   * when omitted — i.e. all user-program output regardless of pipe
   * vs pty mode. Pass `"all"` or include `"system"` to merge
   * runtime/kernel diagnostic lines (timestamps will be a best-effort
   * approximation for unstructured kernel output).
   */
  sources?: ReadonlyArray<LogReadSource>;
}

/**
 * Options for {@link Sandbox.logStream}.
 *
 * All fields optional. `since` and `fromCursor` are mutually
 * exclusive — passing both rejects at the boundary.
 */
export interface LogStreamOptions {
  /** Same shape as {@link LogReadOptions.sources}. */
  sources?: ReadonlyArray<LogReadSource>;

  /**
   * Start at the first entry whose timestamp is `>= since`.
   * Mutually exclusive with {@link fromCursor}.
   */
  since?: Date;

  /**
   * Resume strictly after the entry whose {@link LogEntry.cursor}
   * matches this value. Mutually exclusive with {@link since}.
   */
  fromCursor?: string;

  /** Stop emitting at the first entry whose timestamp is `>= until`. */
  until?: Date;

  /**
   * When `true`, keep the stream open past current EOF and yield
   * new entries as they are written. Defaults to `false`.
   */
  follow?: boolean;
}

/**
 * An async iterable of {@link LogEntry} values.
 *
 * Use `for await...of` to drain, or call {@link recv} directly. The
 * stream ends naturally when the underlying source drains (snapshot
 * mode or `until` reached), and may end early with an error if the
 * follower falls behind the file's rotation retention window.
 */
export class LogStream
  implements AsyncIterable<LogEntry>, AsyncDisposable
{
  private readonly inner: NapiLogStream;
  private done = false;

  /** @internal */
  constructor(inner: NapiLogStream) {
    this.inner = inner;
  }

  async recv(): Promise<LogEntry | null> {
    if (this.done) return null;
    const raw = await withMappedErrors(() => this.inner.recv());
    if (raw === null) {
      this.done = true;
      return null;
    }
    return logEntryFromNapi(raw);
  }

  [Symbol.asyncIterator](): AsyncIterator<LogEntry> {
    return mapAsyncIterable(
      { recv: () => this.inner.recv() },
      logEntryFromNapi,
    )[Symbol.asyncIterator]();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    this.done = true;
  }
}

/** @internal */
export function logEntryFromNapi(raw: NapiLogEntry): LogEntry {
  const source = raw.source as LogSource;
  return new LogEntry(
    new Date(raw.timestampMs),
    source,
    raw.sessionId,
    new Uint8Array(raw.data),
    raw.cursor,
  );
}

/** @internal */
export function logReadOptionsToNapi(
  opts?: LogReadOptions,
): NapiLogOptions | undefined {
  if (!opts) return undefined;
  return {
    tail: opts.tail,
    sinceMs: opts.since?.getTime(),
    untilMs: opts.until?.getTime(),
    sources: opts.sources ? Array.from(opts.sources) : undefined,
  };
}

/** @internal */
export function logStreamOptionsToNapi(
  opts?: LogStreamOptions,
): NapiLogStreamOptions | undefined {
  if (!opts) return undefined;
  return {
    sources: opts.sources ? Array.from(opts.sources) : undefined,
    sinceMs: opts.since?.getTime(),
    fromCursor: opts.fromCursor,
    untilMs: opts.until?.getTime(),
    follow: opts.follow,
  };
}
