import {
  CustomError,
  DatabaseError,
  ExecTimeoutError,
  HttpError,
  ImageError,
  ImageInUseError,
  ImageNotFoundError,
  InvalidConfigError,
  IoError,
  JsonError,
  LibkrunfwNotFoundError,
  MicrosandboxError,
  NixError,
  PatchFailedError,
  ProtocolError,
  RuntimeError,
  SandboxFsError,
  SandboxNotFoundError,
  SandboxStillRunningError,
  TerminalError,
  VolumeAlreadyExistsError,
  VolumeNotFoundError,
} from "../errors.js";

// The native binding emits every error as `[VariantName] message`.
const PATTERN = /^\[(\w+)\] ([\s\S]*)$/;

const CTORS = new Map<string, (msg: string, raw: Error) => MicrosandboxError>([
  ["Io", (m, c) => new IoError(m, { cause: c })],
  ["Http", (m, c) => new HttpError(m, { cause: c })],
  ["LibkrunfwNotFound", (m, c) => new LibkrunfwNotFoundError(m, { cause: c })],
  ["Database", (m, c) => new DatabaseError(m, { cause: c })],
  ["InvalidConfig", (m, c) => new InvalidConfigError(m, { cause: c })],
  ["SandboxNotFound", (m, c) => new SandboxNotFoundError(m, { cause: c })],
  ["SandboxStillRunning", (m, c) => new SandboxStillRunningError(m, { cause: c })],
  ["Runtime", (m, c) => new RuntimeError(m, { cause: c })],
  ["Json", (m, c) => new JsonError(m, { cause: c })],
  ["Protocol", (m, c) => new ProtocolError(m, { cause: c })],
  ["Nix", (m, c) => new NixError(m, { cause: c })],
  ["ExecTimeout", (m, c) => new ExecTimeoutError(m, parseTimeoutMs(m), { cause: c })],
  ["Terminal", (m, c) => new TerminalError(m, { cause: c })],
  ["SandboxFs", (m, c) => new SandboxFsError(m, { cause: c })],
  ["ImageNotFound", (m, c) => new ImageNotFoundError(m, { cause: c })],
  ["ImageInUse", (m, c) => new ImageInUseError(m, { cause: c })],
  ["VolumeNotFound", (m, c) => new VolumeNotFoundError(m, { cause: c })],
  ["VolumeAlreadyExists", (m, c) => new VolumeAlreadyExistsError(m, { cause: c })],
  ["Image", (m, c) => new ImageError(m, { cause: c })],
  ["PatchFailed", (m, c) => new PatchFailedError(m, { cause: c })],
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
  const ctor = CTORS.get(m[1]!);
  if (!ctor) return err;
  return ctor(m[2]!, err);
}

export async function withMappedErrors<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw mapNapiError(e);
  }
}
