import { parseCheckpointRemoval, parseGroupRemoval } from "../snapshot-removal.js";
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
  SnapshotSourceRecoveryError,
  SnapshotImportError,
  SnapshotVerificationError,
  SnapshotRemovalRecoveryError,
  SnapshotGroupRemovalRecoveryError,
  TerminalError,
  UnsupportedOperationError,
  UnsupportedError,
  VolumeAlreadyExistsError,
  VolumeNotFoundError,
} from "../errors.js";
import { parseGroupVerification } from "../snapshot-verification.js";

// The recovery variant carries a JSON envelope after the usual tag; all others carry text.
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
  ["Image", (m, c) => new ImageError(m, { cause: c })],
  ["PatchFailed", (m, c) => new PatchFailedError(m, { cause: c })],
  ["MetricsDisabled", (m, c) => new MetricsDisabledError(m, { cause: c })],
  ["MetricsUnavailable", (m, c) => new MetricsUnavailableError(m, { cause: c })],
  ["UnsupportedOperation", (m, c) => new UnsupportedOperationError(m, { cause: c })],
  ["Unsupported", (m, c) => new UnsupportedError(m, { cause: c })],
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
  if (m[1] === "SnapshotImport") return mapImportError(m[2]!, err);
  if (m[1] === "SnapshotRemovalRecovery") {
    try {
      const envelope = JSON.parse(m[2]!);
      if (typeof envelope.message !== "string" || typeof envelope.detail !== "string") return err;
      return new SnapshotRemovalRecoveryError(envelope.message, parseCheckpointRemoval(envelope.result), envelope.detail, { cause: err });
    } catch { return err; }
  }
  if (m[1] === "SnapshotGroupRemovalRecovery") {
    try {
      const envelope = JSON.parse(m[2]!);
      if (typeof envelope.message !== "string" || typeof envelope.detail !== "string") return err;
      return new SnapshotGroupRemovalRecoveryError(envelope.message, parseGroupRemoval(envelope.result), envelope.detail, { cause: err });
    } catch { return err; }
  }
  if (m[1] === "SnapshotVerification") {
    try {
      const envelope = JSON.parse(m[2]!);
      if (typeof envelope.message !== "string") return err;
      return new SnapshotVerificationError(envelope.message, parseGroupVerification(envelope.report), { cause: err });
    } catch { return err; }
  }
  if (m[1] === "SnapshotSourceRecovery") {
    return mapRecoveryError(m[2]!, err);
  }
  const ctor = CTORS.get(m[1]!);
  if (!ctor) return err;
  return ctor(m[2]!, err);
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
    const head = a?.head_update;
    if (head != null && (typeof head !== "object" || typeof head.group !== "string" ||
        typeof head.reason !== "string" || typeof head.changed !== "boolean" ||
        !(head.previous === null || typeof head.previous === "string") ||
        !(head.head === null || typeof head.head === "string"))) return raw;
    return new SnapshotSourceRecoveryError(envelope.message, {
      sourceSandbox: r.source_sandbox,
      checkpointId: r.checkpoint_id,
      checkpointRoot: r.checkpoint_root,
      checkpointPath: r.checkpoint_path,
      detail: r.detail,
      publicationError: r.publication_error,
      artifact: a === null ? null : {
        kind: a.kind, path: a.path, snapshotId: a.snapshot_id, digest: a.digest,
        ...(a.head_update === undefined ? {} : { headUpdate: head }),
      },
    }, { cause: raw });
  } catch {
    // Preserve the original refusal if a mismatched native binary sends an unknown envelope.
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

function mapImportError(payload: string, raw: Error): unknown {
  try {
    const envelope = JSON.parse(payload);
    const details = envelope.import;
    if (typeof envelope.message !== "string" || !details ||
        typeof details.operation_id !== "string" || typeof details.detail !== "string" ||
        !(details.group_path === null || typeof details.group_path === "string") ||
        !["not_committed", "committed", "unknown"].includes(details.outcome) ||
        !Array.isArray(details.archives) || !details.archives.every((path: unknown) => typeof path === "string")) return raw;
    return new SnapshotImportError(envelope.message, {
      operationId: details.operation_id, archives: details.archives,
      groupPath: details.group_path, outcome: details.outcome, detail: details.detail,
    }, { cause: raw });
  } catch {
    // A mismatched native payload is still a failure, never an inferred successful import.
    return raw;
  }
}
