import {
  CustomError,
  CloudHttpError,
  DatabaseError,
  ExecTimeoutError,
  StopTimeoutError,
  HttpError,
  ImageError,
  ImageInUseError,
  ImageNotFoundError,
  InvalidConfigError,
  NoDefaultCommandError,
  IoError,
  JsonError,
  LibkrunfwNotFoundError,
  MetricsDisabledError,
  MetricsUnavailableError,
  MicrosandboxError,
  ModificationNotConfirmedError,
  NixError,
  PatchFailedError,
  ProtocolError,
  RuntimeError,
  RuntimeIncompleteError,
  RuntimeNotInstalledError,
  SandboxFsOpsError,
  SandboxAlreadyExistsError,
  SandboxNotFoundError,
  SandboxNotRunningError,
  SandboxStopTimedOutError,
  SandboxReplacedError,
  SandboxStillRunningError,
  ServiceAlreadyExistsError,
  ServiceError,
  ServiceNotFoundError,
  SnapshotSourceRecoveryError,
  TerminalError,
  UnsupportedOperationError,
  UnsupportedError,
  VolumeAlreadyExistsError,
  VolumeNotFoundError,
  type ChangeState,
  type ServiceErrorReason,
} from "../errors.js";

// The recovery and Service variants, and any error from a Service change, carry a JSON envelope
// after the usual tag; all others carry text.
const PATTERN = /^\[(\w+)\] ([\s\S]*)$/;

const CTORS = new Map<string, (msg: string, raw: Error) => MicrosandboxError>([
  ["Io", (m, c) => new IoError(m, { cause: c })],
  ["Http", (m, c) => new HttpError(m, { cause: c })],
  ["CloudHttp", (m, c) => new CloudHttpError(m, { cause: c })],
  ["LibkrunfwNotFound", (m, c) => new LibkrunfwNotFoundError(m, { cause: c })],
  ["RuntimeNotInstalled", (m, c) => new RuntimeNotInstalledError(m, { cause: c })],
  ["RuntimeIncomplete", (m, c) => new RuntimeIncompleteError(m, { cause: c })],
  ["Database", (m, c) => new DatabaseError(m, { cause: c })],
  ["InvalidConfig", (m, c) => new InvalidConfigError(m, { cause: c })],
  ["NoDefaultCommand", (m, c) => new NoDefaultCommandError(m, { cause: c })],
  ["SandboxNotFound", (m, c) => new SandboxNotFoundError(m, { cause: c })],
  ["SandboxAlreadyExists", (m, c) => new SandboxAlreadyExistsError(m, { cause: c })],
  ["SandboxReplaced", (m, c) => new SandboxReplacedError(m, { cause: c })],
  ["SandboxStillRunning", (m, c) => new SandboxStillRunningError(m, { cause: c })],
  ["SandboxNotRunning", (m, c) => new SandboxNotRunningError(m, { cause: c })],
  ["SandboxStopTimedOut", (m, c) => new SandboxStopTimedOutError(m, { cause: c })],
  ["Runtime", (m, c) => new RuntimeError(m, { cause: c })],
  ["Json", (m, c) => new JsonError(m, { cause: c })],
  ["Protocol", (m, c) => new ProtocolError(m, { cause: c })],
  ["Nix", (m, c) => new NixError(m, { cause: c })],
  ["ExecTimeout", (m, c) => new ExecTimeoutError(m, parseTimeoutMs(m), { cause: c })],
  ["StopTimeout", (m, c) => new StopTimeoutError(m, { cause: c })],
  ["Terminal", (m, c) => new TerminalError(m, { cause: c })],
  ["SandboxFsOps", (m, c) => new SandboxFsOpsError(m, { cause: c })],
  ["ImageNotFound", (m, c) => new ImageNotFoundError(m, { cause: c })],
  ["ImageInUse", (m, c) => new ImageInUseError(m, { cause: c })],
  ["VolumeNotFound", (m, c) => new VolumeNotFoundError(m, { cause: c })],
  ["VolumeAlreadyExists", (m, c) => new VolumeAlreadyExistsError(m, { cause: c })],
  ["ServiceNotFound", (m, c) => new ServiceNotFoundError(m, { cause: c })],
  ["ServiceAlreadyExists", (m, c) => new ServiceAlreadyExistsError(m, { cause: c })],
  ["Image", (m, c) => new ImageError(m, { cause: c })],
  ["PatchFailed", (m, c) => new PatchFailedError(m, { cause: c })],
  ["MetricsDisabled", (m, c) => new MetricsDisabledError(m, { cause: c })],
  ["MetricsUnavailable", (m, c) => new MetricsUnavailableError(m, { cause: c })],
  ["UnsupportedOperation", (m, c) => new UnsupportedOperationError(m, { cause: c })],
  ["Unsupported", (m, c) => new UnsupportedError(m, { cause: c })],
  ["ModificationNotConfirmed", (m, c) => new ModificationNotConfirmedError(m, { cause: c })],
  ["Custom", (m, c) => new CustomError(m, { cause: c })],
]);

// Rust formats `Duration` as `5s`, `2.5s`, `500ms`, etc. Best-effort parse.
function parseTimeoutMs(message: string): number | null {
  const m = /(\d+(?:\.\d+)?)\s*(ms|s|m|h)\b/.exec(message);
  if (!m) return null;
  const n = Number(m[1]);
  switch (m[2]) {
    case "ms": return n;
    case "s":  return n * 1000;
    case "m":  return n * 60_000;
    case "h":  return n * 3_600_000;
    default:   return null;
  }
}

export function mapNapiError(err: unknown): unknown {
  if (!(err instanceof Error)) return err;
  const m = PATTERN.exec(err.message);
  if (!m) return err;
  if (m[1] === "SnapshotSourceRecovery") {
    return mapRecoveryError(m[2]!, err);
  }
  if (m[1] === "Service") {
    return mapServiceError(m[2]!, err);
  }
  const ctor = CTORS.get(m[1]!);
  if (!ctor) return err;
  const changeError = mapChangeError(m[2]!, err, ctor);
  if (changeError) return changeError;
  return ctor(m[2]!, err);
}

function mapChangeError(
  payload: string,
  raw: Error,
  ctor: (message: string, raw: Error) => MicrosandboxError,
): MicrosandboxError | null {
  try {
    const envelope = JSON.parse(payload);
    if (!envelope || typeof envelope.message !== "string" || !("changed" in envelope)) {
      return null;
    }
    const changed: ChangeState = envelope.changed === "unchanged" ? "unchanged" : "unknown";
    const mapped = ctor(envelope.message, raw);
    Object.defineProperty(mapped, "changed", { value: changed, enumerable: true });
    return mapped;
  } catch {
    return null;
  }
}

function mapRecoveryError(payload: string, raw: Error): unknown {
  try {
    const envelope = JSON.parse(payload);
    const r = envelope.recovery;
    const stringFields = ["source_sandbox", "checkpoint_id", "checkpoint_root", "checkpoint_path", "detail"];
    if (typeof envelope.message !== "string" || !r ||
        !stringFields.every((key) => typeof r[key] === "string") ||
        !(r.publication_error === null || typeof r.publication_error === "string")) return raw;
    const a = r.artifact;
    if (a !== null && (!a || !(a.kind === "installed" || a.kind === "archive") ||
        !["path", "snapshot_id", "digest"].every((key) => typeof a[key] === "string"))) return raw;
    return new SnapshotSourceRecoveryError(envelope.message, {
      sourceSandbox: r.source_sandbox,
      checkpointId: r.checkpoint_id,
      checkpointRoot: r.checkpoint_root,
      checkpointPath: r.checkpoint_path,
      detail: r.detail,
      publicationError: r.publication_error,
      artifact: a === null ? null : {
        kind: a.kind, path: a.path, snapshotId: a.snapshot_id, digest: a.digest,
      },
    }, { cause: raw });
  } catch {
    // Preserve the original refusal if a mismatched native binary sends an unknown envelope.
    return raw;
  }
}

const SERVICE_REASONS: ReadonlySet<string> = new Set<ServiceErrorReason>([
  "serviceQuotaExceeded", "sandboxServiceLimitExceeded", "serviceConflict", "serviceDetached",
  "targetUnreachable", "sandboxNotRunning", "serviceChangesPaused", "outcomeUnknown", "other",
]);

function mapServiceError(payload: string, raw: Error): unknown {
  try {
    const envelope = JSON.parse(payload);
    if (typeof envelope.message !== "string" || typeof envelope.slug !== "string") return raw;
    // A reason or change state this version does not list keeps the details: an unlisted reason
    // is "other", and anything but "unchanged" fails closed to "unknown".
    const reason: ServiceErrorReason = SERVICE_REASONS.has(envelope.reason)
      ? envelope.reason
      : "other";
    const changed: ChangeState = envelope.changed === "unchanged" ? "unchanged" : "unknown";
    const retryAfterMs = typeof envelope.retryAfterMs === "number" ? envelope.retryAfterMs : null;
    const rawCode = typeof envelope.rawCode === "string" ? envelope.rawCode : null;
    const rawStatus = typeof envelope.rawStatus === "number" ? envelope.rawStatus : null;
    const rawMessage = typeof envelope.rawMessage === "string" ? envelope.rawMessage : null;
    return new ServiceError(
      envelope.message,
      {
        slug: envelope.slug,
        reason,
        retryAfterMs,
        changed,
        rawCode,
        rawStatus,
        rawMessage,
      },
      { cause: raw },
    );
  } catch {
    // Preserve the original error if a mismatched native binary sends an unknown envelope.
    return raw;
  }
}

export async function withMappedErrors<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw mapNapiError(e);
  }
}
