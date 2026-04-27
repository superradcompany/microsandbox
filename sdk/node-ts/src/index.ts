// Sandbox lifecycle and execution
export { Sandbox } from "./sandbox.js";
export { SandboxBuilder } from "./sandbox-builder.js";
export { SandboxHandle } from "./sandbox-handle.js";
export type { SandboxConfig } from "./sandbox-config.js";
export { ExecHandle, ExecOutput, ExecSink } from "./exec.js";
export { ExecOptionsBuilder } from "./exec-options-builder.js";
export type { ExecOptions } from "./exec-options-builder.js";
export { AttachOptionsBuilder } from "./attach-options-builder.js";
export type { AttachOptions } from "./attach-options-builder.js";
export { MountBuilder } from "./mount-builder.js";
export { PatchBuilder } from "./patch-builder.js";
export type {
  PatchFileOptions,
  PatchModeOnly,
  PatchReplaceOnly,
} from "./patch-builder.js";
export { RegistryConfigBuilder } from "./registry-config-builder.js";
export type { RegistryConfig } from "./registry-config-builder.js";

// Filesystem
export { FsReadStream, FsWriteSink, SandboxFs } from "./fs.js";

// Volumes
export { Volume } from "./volume.js";
export { VolumeBuilder } from "./volume-builder.js";
export type { VolumeConfig } from "./volume-builder.js";
export { VolumeHandle } from "./volume-handle.js";
export {
  VolumeFs,
  VolumeFsReadStream,
  VolumeFsWriteSink,
} from "./volume-fs.js";

// Image management
export { Image, ImageHandle } from "./image.js";
export type {
  ImageConfigDetail,
  ImageDetail,
  ImageLayerDetail,
} from "./image.js";

// Metrics streaming
export { MetricsStream } from "./metrics-stream.js";

// Networking
export { NetworkBuilder } from "./network-builder.js";
export { DnsBuilder } from "./dns-builder.js";
export { TlsBuilder } from "./tls-builder.js";
export { SecretBuilder } from "./secret-builder.js";
export type {
  DnsConfig,
  NetworkConfig,
  PublishedPort,
  SecretEntry,
  SecretInjection,
  TlsConfig,
} from "./network-config.js";

// Setup + module-level helpers
export { Setup, install, isInstalled, setup } from "./setup.js";
export { allSandboxMetrics } from "./all-metrics.js";

// Errors
export {
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
} from "./errors.js";
export type { MicrosandboxErrorCode } from "./errors.js";

// Sizes
export { GiB, KiB, MiB, TiB } from "./size.js";
export type { Mebibytes } from "./size.js";

// Logging / pull policy / sandbox status
export { LogLevels } from "./log-level.js";
export type { LogLevel } from "./log-level.js";
export { PullPolicies } from "./pull-policy.js";
export type { PullPolicy } from "./pull-policy.js";
export { SandboxStatuses } from "./sandbox-status.js";
export type { SandboxStatus } from "./sandbox-status.js";

// Exec
export type { ExitStatus } from "./exit-status.js";
export type { ExecEvent } from "./exec-event.js";
export { Stdin } from "./stdin.js";
export type { StdinMode } from "./stdin.js";
export type { Rlimit, RlimitResource } from "./rlimit.js";

// Filesystem
export type { FsEntry, FsEntryKind, FsMetadata } from "./fs-types.js";

// Mounts / rootfs / patches / registry
export { DiskImageFormats, intoRootfsSource } from "./rootfs.js";
export type { DiskImageFormat, RootfsSource } from "./rootfs.js";
export type { VolumeMount } from "./mount.js";
export type { Patch } from "./patch.js";
export type { RegistryAuth } from "./registry.js";

// Metrics
export type { SandboxMetrics } from "./metrics.js";

// Pull progress
export type { PullProgress } from "./pull-progress.js";

// Network policy
export { ViolationActions } from "./violation-action.js";
export type { ViolationAction } from "./violation-action.js";
export { DestinationGroups } from "./policy/types.js";
export type {
  Action,
  DestinationGroup,
  Direction,
  Protocol,
} from "./policy/types.js";

// `Destination`, `NetworkPolicy`, `PortRange`, `Rule` each merge an
// interface (the value shape) with a factory namespace (the constructors)
// under one name.
import * as _Factories from "./policy/factories.js";
import type * as _Types from "./policy/types.js";

export const Destination = _Factories.Destination;
export type Destination = _Types.Destination;

export const NetworkPolicy = _Factories.NetworkPolicy;
export type NetworkPolicy = _Types.NetworkPolicy;

export const PortRange = _Factories.PortRange;
export type PortRange = _Types.PortRange;

export const Rule = _Factories.Rule;
export type Rule = _Types.Rule;
