export type MicrosandboxErrorCode =
  | "io"
  | "http"
  | "cloudHttp"
  | "libkrunfwNotFound"
  | "runtimeNotInstalled"
  | "runtimeIncomplete"
  | "database"
  | "invalidConfig"
  | "noDefaultCommand"
  | "sandboxNotFound"
  | "sandboxAlreadyExists"
  | "sandboxReplaced"
  | "sandboxStillRunning"
  | "sandboxNotRunning"
  | "sandboxStopTimedOut"
  | "runtime"
  | "json"
  | "protocol"
  | "nix"
  | "execTimeout"
  | "stopTimeout"
  | "terminal"
  | "sandboxFsOps"
  | "imageNotFound"
  | "imageInUse"
  | "volumeNotFound"
  | "volumeAlreadyExists"
  | "serviceNotFound"
  | "serviceAlreadyExists"
  | "service"
  | "image"
  | "patchFailed"
  | "snapshotSourceRecovery"
  | "metricsDisabled"
  | "metricsUnavailable"
  | "unsupportedOperation"
  | "unsupported"
  | "modificationNotConfirmed"
  | "custom";

/** Whether a failed Service change may have been applied. */
export type ChangeState = "unchanged" | "unknown";

interface ChangeErrorOptions extends ErrorOptions {
  changed?: ChangeState;
}

export class MicrosandboxError extends Error {
  readonly code: MicrosandboxErrorCode;
  /** Present when this error was returned by a Service change. */
  readonly changed?: ChangeState;

  constructor(code: MicrosandboxErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    this.changed = (options as ChangeErrorOptions | undefined)?.changed;
    this.name = new.target.name;
  }
}

export class IoError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("io", message, options);
  }
}

export class HttpError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("http", message, options);
  }
}

export class CloudHttpError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("cloudHttp", message, options);
  }
}

export class LibkrunfwNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("libkrunfwNotFound", message, options);
  }
}

export class RuntimeNotInstalledError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("runtimeNotInstalled", message, options);
  }
}

export class RuntimeIncompleteError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("runtimeIncomplete", message, options);
  }
}

export class DatabaseError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("database", message, options);
  }
}

export class InvalidConfigError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("invalidConfig", message, options);
  }
}

export class NoDefaultCommandError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("noDefaultCommand", message, options);
  }
}

export class SandboxNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxNotFound", message, options);
  }
}

export class SandboxAlreadyExistsError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxAlreadyExists", message, options);
  }
}

export class SandboxReplacedError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxReplaced", message, options);
  }
}

export class SandboxStillRunningError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxStillRunning", message, options);
  }
}

export class SandboxNotRunningError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxNotRunning", message, options);
  }
}

export class SandboxStopTimedOutError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxStopTimedOut", message, options);
  }
}

export class RuntimeError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("runtime", message, options);
  }
}

export class JsonError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("json", message, options);
  }
}

export class ProtocolError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("protocol", message, options);
  }
}

export class NixError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("nix", message, options);
  }
}

export class ExecTimeoutError extends MicrosandboxError {
  readonly timeoutMs: number | null;

  constructor(message: string, timeoutMs: number | null = null, options?: ErrorOptions) {
    super("execTimeout", message, options);
    this.timeoutMs = timeoutMs;
  }
}

/** Graceful shutdown exceeded its budget; the sandbox was not implicitly killed. */
export class StopTimeoutError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("stopTimeout", message, options);
  }
}

export class TerminalError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("terminal", message, options);
  }
}

export class SandboxFsOpsError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxFsOps", message, options);
  }
}

export class ImageNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("imageNotFound", message, options);
  }
}

export class ImageInUseError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("imageInUse", message, options);
  }
}

export class VolumeNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("volumeNotFound", message, options);
  }
}

export class VolumeAlreadyExistsError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("volumeAlreadyExists", message, options);
  }
}

/** No visible Service has this slug. */
export class ServiceNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("serviceNotFound", message, options);
  }
}

/** The slug is unavailable. */
export class ServiceAlreadyExistsError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("serviceAlreadyExists", message, options);
  }
}

/**
 * Why a Service change did not complete. `"other"` is unrecognized; `changed` still reports
 * the outcome.
 */
export type ServiceErrorReason =
  | "serviceQuotaExceeded"
  | "sandboxServiceLimitExceeded"
  | "serviceConflict"
  | "serviceDetached"
  | "targetUnreachable"
  | "sandboxNotRunning"
  | "serviceChangesPaused"
  | "outcomeUnknown"
  | "other";

/** Details reported with a Service change error. */
export interface ServiceErrorDetails {
  /** Slug of the Service the change addressed. */
  readonly slug: string;
  readonly reason: ServiceErrorReason;
  /** Retry delay returned with the refusal, in milliseconds, or `null`. */
  readonly retryAfterMs: number | null;
  readonly changed: ChangeState;
  /** Raw refusal code when `reason` is `"other"`, otherwise `null`. */
  readonly rawCode: string | null;
  /** Raw HTTP status when `reason` is `"other"`, otherwise `null`. */
  readonly rawStatus: number | null;
  /** Raw refusal message when `reason` is `"other"`, otherwise `null`. */
  readonly rawMessage: string | null;
}

/** A Service change was refused, or its outcome is unknown. */
export class ServiceError extends MicrosandboxError {
  readonly slug: string;
  readonly reason: ServiceErrorReason;
  readonly retryAfterMs: number | null;
  override readonly changed: ChangeState;
  readonly rawCode: string | null;
  readonly rawStatus: number | null;
  readonly rawMessage: string | null;

  constructor(
    message: string,
    details: ServiceErrorDetails,
    options?: ErrorOptions,
  ) {
    super("service", message, withChangeState(options, details.changed));
    this.slug = details.slug;
    this.reason = details.reason;
    this.retryAfterMs = details.retryAfterMs;
    this.changed = details.changed;
    this.rawCode = details.rawCode;
    this.rawStatus = details.rawStatus;
    this.rawMessage = details.rawMessage;
  }
}

function withChangeState(options: ErrorOptions | undefined, changed: ChangeState): ErrorOptions {
  const changeOptions: ChangeErrorOptions = { ...options, changed };
  return changeOptions;
}

export class ImageError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("image", message, options);
  }
}

export class PatchFailedError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("patchFailed", message, options);
  }
}

export class MetricsDisabledError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("metricsDisabled", message, options);
  }
}

/** An artifact successfully published despite failure to recover the source. */
export interface PublishedSnapshotArtifact {
  readonly kind: "installed" | "archive";
  readonly path: string;
  readonly snapshotId: string;
  readonly digest: string;
}

/** Recovery locators do not imply that the source is running or safe to resume. */
export interface SnapshotSourceRecoveryDetails {
  readonly sourceSandbox: string;
  readonly checkpointId: string;
  readonly checkpointRoot: string;
  readonly checkpointPath: string;
  readonly artifact: PublishedSnapshotArtifact | null;
  readonly detail: string;
  readonly publicationError: string | null;
}

/** Capture succeeded, but the source did not recover its prior execution state. */
export class SnapshotSourceRecoveryError extends MicrosandboxError {
  constructor(
    message: string,
    readonly recovery: SnapshotSourceRecoveryDetails,
    options?: ErrorOptions,
  ) {
    super("snapshotSourceRecovery", message, options);
  }
}

export class MetricsUnavailableError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("metricsUnavailable", message, options);
  }
}

export class UnsupportedOperationError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("unsupportedOperation", message, options);
  }
}

export class UnsupportedError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("unsupported", message, options);
  }
}

export class ModificationNotConfirmedError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("modificationNotConfirmed", message, options);
  }
}

export class CustomError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("custom", message, options);
  }
}
