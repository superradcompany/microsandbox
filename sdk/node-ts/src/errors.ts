export type MicrosandboxErrorCode =
  | "io"
  | "http"
  | "libkrunfwNotFound"
  | "database"
  | "invalidConfig"
  | "sandboxNotFound"
  | "sandboxStillRunning"
  | "runtime"
  | "json"
  | "protocol"
  | "nix"
  | "execTimeout"
  | "terminal"
  | "sandboxFs"
  | "imageNotFound"
  | "imageInUse"
  | "volumeNotFound"
  | "volumeAlreadyExists"
  | "image"
  | "patchFailed"
  | "custom";

export class MicrosandboxError extends Error {
  readonly code: MicrosandboxErrorCode;

  constructor(code: MicrosandboxErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
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

export class LibkrunfwNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("libkrunfwNotFound", message, options);
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

export class SandboxNotFoundError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxNotFound", message, options);
  }
}

export class SandboxStillRunningError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxStillRunning", message, options);
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

export class TerminalError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("terminal", message, options);
  }
}

export class SandboxFsError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("sandboxFs", message, options);
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

export class CustomError extends MicrosandboxError {
  constructor(message: string, options?: ErrorOptions) {
    super("custom", message, options);
  }
}
