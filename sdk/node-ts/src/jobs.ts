import type { NapiJob, NapiJobAttachment, NapiJobLogStream } from "./internal/napi.js";

export type JobState = "starting" | "running" | "exited" | "failed" | "lost";

export interface JobInfo {
  readonly id: string;
  readonly runtimeBootId: string;
  readonly command: readonly string[];
  readonly state: JobState;
  readonly tty: boolean;
  readonly stdinClosed: boolean;
  readonly pid: number | null;
  /** Unix milliseconds. */
  readonly createdAt: number;
  readonly startedAt: number | null;
  readonly finishedAt: number | null;
  readonly exitCode: number | null;
  readonly timedOut: boolean;
  readonly error: string | null;
  readonly failure: { kind: string; message: string; errno?: number; errno_name?: string; stage?: string } | null;
}
export interface JobPage { readonly items: readonly JobInfo[]; readonly nextCursor: string | null }
export interface JobExit { readonly code: number; readonly success: boolean; readonly timedOut: boolean }
export interface JobLogEntry {
  readonly timestamp: number;
  readonly source: string;
  readonly data: Buffer;
  readonly cursor: string;
}
export interface JobLogOptions {
  tail?: number;
  since?: number;
  until?: number;
  sources?: string[];
  fromCursor?: string;
  follow?: boolean;
}
export type JobEvent =
  | { type: "output"; value: JobLogEntry }
  | { type: "gap"; value: { cursor: string } }
  | { type: "completed"; value: JobInfo };

/** A stable job error code; uncertain launch errors include the recoverable job ID. */
export class JobError extends Error {
  constructor(readonly code: string, message: string, readonly jobId?: string) {
    super(message);
    this.name = "JobError";
  }
}

export class JobListBuilder {
  /** @internal */ includeAll = false;
  /** @internal */ pageSize = 50;
  /** @internal */ after?: string;
  all(value = true): this { this.includeAll = value; return this; }
  limit(value: number): this { this.pageSize = value; return this; }
  cursor(value: string): this { this.after = value; return this; }
}

export class JobAttachOptionsBuilder {
  /** @internal */ observer = false;
  /** @internal */ bytes?: number;
  /** @internal */ after?: string;
  readOnly(value = true): this { this.observer = value; return this; }
  replayRecent(maxBytes: number): this { this.bytes = maxBytes; this.after = undefined; return this; }
  replayAfter(cursor: string): this { this.after = cursor; this.bytes = undefined; return this; }
}

/** Sandbox-bound process identity. Releasing this object never stops the job or sandbox. */
export class Job {
  readonly id: string;
  /** @internal */
  constructor(private readonly inner: NapiJob) { this.id = inner.id; }
  async inspect(): Promise<JobInfo> { return jobInfoFromJson(await jobCall(() => this.inner.inspect())); }
  async wait(): Promise<JobExit> {
    const raw = JSON.parse(await jobCall(() => this.inner.wait())) as { code: number; success: boolean; timed_out: boolean };
    return { code: raw.code, success: raw.success, timedOut: raw.timed_out };
  }
  async signal(signal: number): Promise<void> { await jobCall(() => this.inner.signal(signal)); }
  async kill(): Promise<void> { await jobCall(() => this.inner.kill()); }
  async eof(): Promise<void> { await jobCall(() => this.inner.eof()); }
  async logs(options: JobLogOptions = {}): Promise<JobLogEntry[]> {
    const raw = JSON.parse(await jobCall(() => this.inner.logs(logOptions(options)))) as RawLog[];
    return raw.map(logEntry);
  }
  async logStream(options: JobLogOptions = {}): Promise<JobLogStream> {
    return new JobLogStream(await jobCall(() => this.inner.logStream(logOptions(options))));
  }
  async followLogs(options: JobLogOptions = {}): Promise<JobLogStream> { return this.logStream({ ...options, follow: true }); }
  async attach(): Promise<JobAttachment> { return this.attachWith(b => b); }
  async attachWith(configure: (b: JobAttachOptionsBuilder) => JobAttachOptionsBuilder): Promise<JobAttachment> {
    const b = configure(new JobAttachOptionsBuilder());
    return new JobAttachment(await jobCall(() => this.inner.attach(b.observer, b.bytes, b.after)));
  }
}

/** One input owner or read-only observer. recv may run concurrently with input and detach. */
export class JobAttachment implements AsyncIterable<JobEvent>, AsyncDisposable {
  /** @internal */
  constructor(private readonly inner: NapiJobAttachment) {}
  async recv(): Promise<JobEvent | null> {
    const raw = await jobCall(() => this.inner.recv());
    if (raw === null) return null;
    const event = JSON.parse(raw) as { type: JobEvent["type"]; value: unknown };
    switch (event.type) {
      case "output": return { type: event.type, value: logEntry(event.value as RawLog) };
      case "completed": return { type: event.type, value: jobInfo(event.value as RawInfo) };
      case "gap": return { type: event.type, value: event.value as { cursor: string } };
    }
  }
  /** Each call admits at most 16 KiB atomically. An empty buffer never sends EOF. */
  async writeStdin(data: Uint8Array): Promise<void> { await jobCall(() => this.inner.writeStdin(Buffer.from(data))); }
  async resize(rows: number, cols: number): Promise<void> { await jobCall(() => this.inner.resize(rows, cols)); }
  async detach(): Promise<void> { await jobCall(() => this.inner.detach()); }
  async [Symbol.asyncDispose](): Promise<void> { await this.detach(); }
  async *[Symbol.asyncIterator](): AsyncGenerator<JobEvent> {
    try { for (;;) { const event = await this.recv(); if (!event) break; yield event; } }
    finally { await this.detach(); }
  }
}

export class JobLogStream implements AsyncIterable<JobLogEntry>, AsyncDisposable {
  /** @internal */
  constructor(private readonly inner: NapiJobLogStream) {}
  async next(): Promise<JobLogEntry | null> {
    const raw = await jobCall(() => this.inner.next());
    return raw === null ? null : logEntry(JSON.parse(raw) as RawLog);
  }
  async close(): Promise<void> { await jobCall(() => this.inner.close()); }
  async [Symbol.asyncDispose](): Promise<void> { await this.close(); }
  async *[Symbol.asyncIterator](): AsyncGenerator<JobLogEntry> {
    try { for (;;) { const entry = await this.next(); if (!entry) break; yield entry; } }
    finally { await this.close(); }
  }
}

type RawInfo = Omit<JobInfo, "runtimeBootId" | "stdinClosed" | "createdAt" | "startedAt" | "finishedAt" | "exitCode" | "timedOut"> & {
  runtime_boot_id: string; stdin_closed: boolean; created_at: number;
  started_at: number | null; finished_at: number | null; exit_code: number | null; timed_out: boolean;
};
type RawLog = Omit<JobLogEntry, "data"> & { data_base64: string };
function logEntry(raw: RawLog): JobLogEntry { return { timestamp: raw.timestamp, source: raw.source, cursor: raw.cursor, data: Buffer.from(raw.data_base64, "base64") }; }
function jobInfo(raw: RawInfo): JobInfo {
  return { id: raw.id, runtimeBootId: raw.runtime_boot_id, command: raw.command, state: raw.state, tty: raw.tty,
    stdinClosed: raw.stdin_closed, pid: raw.pid, createdAt: raw.created_at, startedAt: raw.started_at,
    finishedAt: raw.finished_at, exitCode: raw.exit_code, timedOut: raw.timed_out, error: raw.error, failure: raw.failure };
}
/** @internal */
export function jobInfoFromJson(raw: string): JobInfo { return jobInfo(JSON.parse(raw) as RawInfo); }
/** @internal */
export function jobPageFromJson(raw: string): JobPage {
  const page = JSON.parse(raw) as { items: RawInfo[]; next_cursor: string | null };
  return { items: page.items.map(jobInfo), nextCursor: page.next_cursor };
}
function logOptions(options: JobLogOptions): string {
  const { fromCursor, ...rest } = options;
  return JSON.stringify({ ...rest, from_cursor: fromCursor });
}
/** @internal */
export async function jobCall<T>(call: () => Promise<T>): Promise<T> {
  try { return await call(); }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const at = message.indexOf("[Job] ");
    if (at >= 0) {
      const raw = JSON.parse(message.slice(at + 6)) as { code: string; message: string; jobId?: string };
      throw new JobError(raw.code, raw.message, raw.jobId);
    }
    throw error;
  }
}
