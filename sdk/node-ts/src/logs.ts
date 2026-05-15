import type { LogEntry as NapiLogEntry, LogOptions as NapiLogOptions } from "./internal/napi.js";

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

  constructor(
    timestamp: Date,
    source: LogSource,
    sessionId: number | null,
    data: Uint8Array,
  ) {
    this.timestamp = timestamp;
    this.source = source;
    this.sessionId = sessionId;
    this.data = data;
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

/** @internal */
export function logEntryFromNapi(raw: NapiLogEntry): LogEntry {
  const source = raw.source as LogSource;
  return new LogEntry(
    new Date(raw.timestampMs),
    source,
    raw.sessionId,
    new Uint8Array(raw.data),
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
