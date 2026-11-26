import { napi } from "./internal/napi.js";
import { nativeConstructor, optionsBinding } from "./internal/provider.js";

// Low-level agent client (raw transport to agentd).
export {
  AgentClient,
  AgentStream,
  FLAG_SESSION_START,
  FLAG_SHUTDOWN,
  FLAG_TERMINAL,
  type AgentConnectOptions,
  type RawFrame,
} from "./agent.js";
export { SecretSource } from "./network-config.js";
export type { OutboundProxy, SecretSubstitution } from "./network-config.js";
export type { DeploymentProfile } from "./deployment-profile.js";

// Sandbox lifecycle and execution
export { PullProgressCreate, Sandbox, SandboxListBuilder } from "./sandbox.js";
export type { CommandArgs, RestoreBuilder } from "./sandbox.js";
import { Sandbox as _Sandbox, type SandboxBuilder as _SBT } from "./sandbox.js";
/**
 * Native fluent builder for a sandbox. `new SandboxBuilder(name)` is
 * equivalent to `Sandbox.builder(name)` — both return the same shape
 * with `.create()` resolving to a TS `Sandbox`. Names are limited to
 * 128 UTF-8 bytes.
 */
export const SandboxBuilder = function SandboxBuilder(
  this: unknown,
  name: string,
) {
  return _Sandbox.builder(name);
} as unknown as new (name: string) => _SBT;
export type SandboxBuilder = _SBT;
export type {
  CpuPlacement,
  SandboxConfig,
  SandboxPage,
  SandboxInfo,
  SandboxPingResult,
  SandboxTouchResult,
  ExternalMountWarning,
  ForkOptions,
  ForkOutcome,
  BranchOutcome,
} from "./sandbox.js";
export type {
  ChangeKind,
  ConfigPlannedChange,
  ModificationConflict,
  ModificationDisposition,
  ModificationPolicy,
  ModificationWarning,
  ModifyOptions,
  ModifyPort,
  ModifyPortEndpoint,
  PlannedChange,
  ResourceConvergenceState,
  ResourceKind,
  ResourceResizeStatus,
  SandboxModificationPlan,
  SecretChangeKind,
  SecretModifySpec,
  SecretPlannedChange,
} from "./modify.js";
export {
  type DestroyOptions,
  type RestartOptions,
} from "./lifecycle.js";
export { ExecHandle, ExecOutput, ExecSink } from "./exec.js";

// SSH
export { SandboxSshOps, SftpClient, SshClient, SshServer } from "./ssh.js";
export type {
  SshAttachOptions,
  SshClientOptions,
  SshExecOptions,
  SshOutput,
  SshServerOptions,
} from "./ssh.js";

// Filesystem
export { FsReadStream, FsWriteSink, SandboxFsOps } from "./fs.js";

// Volumes
export { Volume, type VolumeInfo, type VolumeKind } from "./volume.js";
import { Volume as _Volume, type VolumeBuilder as _VBT } from "./volume.js";
/**
 * Native fluent builder for a named volume. `new VolumeBuilder(name)`
 * is equivalent to `Volume.builder(name)`.
 */
export const VolumeBuilder = function VolumeBuilder(
  this: unknown,
  name: string,
) {
  return _Volume.builder(name);
} as unknown as new (name: string) => _VBT;
export type VolumeBuilder = _VBT;
export {
  VolumeFs,
  VolumeFsReadStream,
  VolumeFsWriteSink,
} from "./volume-fs.js";

// Services
export { Service, ServiceBuilder, ServiceListBuilder } from "./service.js";
export type {
  ServicePage,
  ServiceStatus,
  ServiceTarget,
  ServiceUpdateOptions,
} from "./service.js";

// Snapshots
export type { SnapshotGroupInfo, SnapshotSourceBinding, SnapshotSourceStatus } from "./snapshot-inspection.js";
export type { CheckpointRemoveResult, SnapshotRemoveResult } from "./snapshot-removal.js";
export { Snapshot as Checkpoint, CheckpointRemoveOptions, SnapshotSaveOptions, SnapshotArchive } from "./snapshot.js";
export { Snapshot, SnapshotCaptureOptions, SnapshotLoadOptions } from "./snapshot-group.js";
export type { SnapshotCreateResult, CheckpointCaptureResult, SnapshotImportResult } from "./snapshot-group.js";
export type { SnapshotGroupVerifyReport, CheckpointVerification, SnapshotVerificationFinding, SnapshotVerificationFindingKind, SnapshotVerificationState } from "./snapshot-verification.js";
export type { DiskCompactionOptions, DiskCompactionDiskResult, DiskCompactionResult } from "./compact.js";
import { Snapshot as _Snapshot, type SnapshotBuilder as _SnapBT } from "./snapshot.js";
/**
 * Native fluent builder for a snapshot. `new SnapshotBuilder(name)`
 * is equivalent to `Checkpoint.builder(name)`.
 */
export const SnapshotBuilder = function SnapshotBuilder(
  this: unknown,
  name = "",
) {
  return _Snapshot.builder(name);
} as unknown as new (name?: string) => _SnapBT;
export type SnapshotBuilder = _SnapBT;
export type {
  SaveOpts,
  LoadOpts,
  HeadUpdate,
  SnapshotCopyBuilder,
  SnapshotScope,
  GuestFlush,
  SnapshotState,
  SnapshotVerifyReport,
  SnapshotVerifyCoverage,
} from "./snapshot.js";

// Local storage observations and runtime cache cleanup
export { Storage } from "./storage.js";
export type {
  StorageUsage,
  StorageCategoryUsage,
  StorageItemUsage,
  StoragePruneOptions,
  MemoryCacheKind,
  MemoryCacheState,
  MemoryCacheEntry,
  MemoryCacheReport,
} from "./storage.js";

// Image management
export { Image, ImageHandle } from "./image.js";
export type {
  ImageConfigDetail,
  ImageDetail,
  ImageLayerDetail,
  ImagePruneReport,
} from "./image.js";

// Logs
export { LogEntry, LogStream } from "./logs.js";
export type {
  LogReadOptions,
  LogReadSource,
  LogSource,
  LogStreamOptions,
} from "./logs.js";

// Metrics streaming
export { MetricsStream } from "./metrics-stream.js";

export const DnsBuilder = nativeConstructor("DnsBuilder");
export const HttpBuilder = nativeConstructor("HttpBuilder");
export const TlsBuilder = nativeConstructor("TlsBuilder");
export const SecretBuilder = nativeConstructor("SecretBuilder");
export const NetworkBuilder = nativeConstructor("NetworkBuilder");
export const OutboundProxyBuilder = nativeConstructor("OutboundProxyBuilder");
export const HttpConnectProxyBuilder = nativeConstructor("HttpConnectProxyBuilder");
export const Socks4ProxyBuilder = nativeConstructor("Socks4ProxyBuilder");
export const Socks5ProxyBuilder = nativeConstructor("Socks5ProxyBuilder");
export const MountBuilder = nativeConstructor("MountBuilder");
export const PatchBuilder = nativeConstructor("PatchBuilder");
export const RegistryConfigBuilder = nativeConstructor("RegistryConfigBuilder");
export const ImageBuilder = nativeConstructor("ImageBuilder");
export const RootDiskBuilder = nativeConstructor("RootDiskBuilder");
export type RootDiskBuilder = NapiRootDiskBuilder;
export const ExecOptionsBuilder = nativeConstructor("ExecOptionsBuilder");
export const InitOptionsBuilder = nativeConstructor("InitOptionsBuilder");
export const AttachOptionsBuilder = nativeConstructor("AttachOptionsBuilder");
import type {
  NapiNetworkPolicyBuilder,
  NapiHttpConnectProxyBuilder,
  NapiOutboundProxyBuilder,
  NapiRootDiskBuilder,
  NapiInitOptionsBuilder,
  NapiRuleBuilder,
  NapiRuleDestinationBuilder,
  NapiSocks4ProxyBuilder,
  NapiSocks5ProxyBuilder,
} from "./internal/napi.js";
export type OutboundProxyBuilder = NapiOutboundProxyBuilder;
export type HttpConnectProxyBuilder = NapiHttpConnectProxyBuilder;
export type Socks4ProxyBuilder = NapiSocks4ProxyBuilder;
export type Socks5ProxyBuilder = NapiSocks5ProxyBuilder;
export const NetworkPolicyBuilder = nativeConstructor("NetworkPolicyBuilder");
export type NetworkPolicyBuilder = NapiNetworkPolicyBuilder;
export const RuleBuilder = nativeConstructor("RuleBuilder");
export type RuleBuilder = NapiRuleBuilder;
export const RuleDestinationBuilder = nativeConstructor("RuleDestinationBuilder");
export type RuleDestinationBuilder = NapiRuleDestinationBuilder;
import type {
  NapiInterfaceOverridesBuilder,
  NapiNetworkRateLimiterBuilder,
  NapiPullProgressEvent,
  NapiPullProgressStream,
  NapiRateLimiterBuilder,
  NapiVolumeMount,
} from "./internal/napi.js";
export const InterfaceOverridesBuilder = nativeConstructor("InterfaceOverridesBuilder");
export type InterfaceOverridesBuilder = NapiInterfaceOverridesBuilder;
export const NetworkRateLimiterBuilder = nativeConstructor("NetworkRateLimiterBuilder");
export type NetworkRateLimiterBuilder = NapiNetworkRateLimiterBuilder;
export const RateLimiterBuilder = nativeConstructor("RateLimiterBuilder");
export type RateLimiterBuilder = NapiRateLimiterBuilder;
export type PullProgressEvent = NapiPullProgressEvent;
export type PullProgressStream = NapiPullProgressStream;

// Setup + module-level helpers
export { resolveRuntimeVersion, resolveRuntime, isRuntimeInstalled, installRuntime, ensureRuntime } from "./setup.js";
export type { RuntimeConfig, InstallOptions, ResolvedRuntime, RuntimeOrigin } from "./setup.js";
export { allSandboxMetrics } from "./all-metrics.js";

/** Override the `libkrunfw` shared library path used by subsequently created local sandboxes. */
export function setRuntimeLibkrunfwPath(path: string): void {
  const setter = napi.setRuntimeLibkrunfwPath;
  if (!setter) {
    throw new Error("native binding does not expose setRuntimeLibkrunfwPath");
  }
  setter(path);
}

// Errors
export {
  AgentClientError,
  BootStartError,
  ExecFailedError,
  InvalidCursorError,
  MissedRotationError,
  NetworkBuilderError,
  SnapshotAlreadyExistsError,
  SnapshotImageMissingError,
  SnapshotIntegrityError,
  SnapshotMigrationError,
  SnapshotNotFoundError,
  SnapshotSandboxRunningError,
  WindowsHostSetupError,
  CustomError,
  CloudHttpError,
  DatabaseError,
  ExecTimeoutError,
  StopTimeoutError,
  ResizeTimeoutError,
  ResizeWaitError,
  type ResizeWaitFailure,
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
  SnapshotImportError,
  SnapshotVerificationError,
  SnapshotRemovalRecoveryError,
  SnapshotGroupRemovalRecoveryError,
  TerminalError,
  UnsupportedOperationError,
  UnsupportedError,
  VolumeAlreadyExistsError,
  VolumeNotFoundError,
} from "./errors.js";
export type {
  ChangeState,
  MicrosandboxErrorCode,
  PublishedSnapshotArtifact,
  ServiceErrorDetails,
  ServiceErrorReason,
  SnapshotSourceRecoveryDetails,
  SnapshotImportDetails,
  SnapshotImportOutcome,
} from "./errors.js";

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
export {
  DiskImageFormats,
  RootfsSourceKinds,
  intoRootfsSource,
} from "./rootfs.js";
export type {
  DiskImageFormat,
  RootfsSource,
  RootfsSourceKind,
} from "./rootfs.js";
// Volume mount + patch types come from the napi-emitted .d.ts so the
// MountBuilder.build() / PatchBuilder.build() return types are
// consistent with what each other native builder emits (TlsConfig /
// DnsConfig / SecretEntry / VolumeMount / Patch — all flat shapes
// with `kind` discriminator + per-variant fields).
export type { NapiOwnedVolumeOptions as OwnedVolumeOptions } from "./internal/napi.js";
export type VolumeMountKind = "bind" | "named" | "owned" | "tmpfs" | "disk";
export const VolumeMountKinds: readonly VolumeMountKind[] = [
  "bind",
  "named",
  "owned",
  "tmpfs",
  "disk",
] as const;
export type VolumeMount = NapiVolumeMount;
/** Per-mount stat-virtualization policy for virtiofs-backed mounts. */
export type StatVirtualization = "strict" | "relaxed" | "off";
export const StatVirtualizations: readonly StatVirtualization[] = [
  "strict",
  "relaxed",
  "off",
] as const;
/** Per-mount host-permission policy for virtiofs-backed mounts. */
export type HostPermissions = "private" | "mirror";
export const HostPermissionsList: readonly HostPermissions[] = [
  "private",
  "mirror",
] as const;
export type PatchKind =
  | "text"
  | "file"
  | "copyFile"
  | "copyDir"
  | "symlink"
  | "mkdir"
  | "remove"
  | "append";
export const PatchKinds: readonly PatchKind[] = [
  "text",
  "file",
  "copyFile",
  "copyDir",
  "symlink",
  "mkdir",
  "remove",
  "append",
] as const;
export { RegistryAuthKinds } from "./registry.js";
export type { RegistryAuth, RegistryAuthKind } from "./registry.js";

// Metrics
export type { SandboxMetrics } from "./metrics.js";

// Pull progress
export type { PullProgress } from "./pull-progress.js";
export { CreationProgressCreate } from "./sandbox.js";
export type { CreationProgress, CreationProgressStream, StartupPhase } from "./creation-progress.js";

// Network policy
export { ViolationActions } from "./violation-action.js";
export type { ViolationAction } from "./violation-action.js";
export { DestinationGroups } from "./policy/types.js";
export type {
  Action,
  DestinationGroup,
  Direction,
  NetworkProfile,
  Protocol,
} from "./policy/types.js";

// `Destination`, `NetworkPolicy`, `PortRange`, and `Rule` each merge an
// interface (the value shape) with a factory namespace (the constructors)
// under one name.
import * as _Factories from "./policy/factories.js";
import type * as _Types from "./policy/types.js";

export const Destination = _Factories.Destination;
export type Destination = _Types.Destination;

export const NetworkPolicy = {
  ..._Factories.NetworkPolicy,
  /**
   * Start building a `NetworkPolicy` via the native fluent builder.
   * Equivalent to `new NetworkPolicyBuilder()`.
   */
  builder: (): NapiNetworkPolicyBuilder => new (optionsBinding().NetworkPolicyBuilder)(),
};
export type NetworkPolicy = _Types.NetworkPolicy;

export const PortRange = _Factories.PortRange;
export type PortRange = _Types.PortRange;

export const Rule = _Factories.Rule;
export type Rule = _Types.Rule;

export { Job, JobAttachment, JobError, JobLogStream, JobListBuilder, JobAttachOptionsBuilder } from "./jobs.js";
export type { JobInfo, JobPage, JobExit, JobLogEntry, JobLogOptions, JobEvent, JobState, JobOutputSource } from "./jobs.js";

export type {
  ResizeOutcome,
  ResizeObservation,
  ResizeTarget,
  ResizeOperation,
  SandboxModificationResult,
} from "./resize.js";

export { diagnoseStorage } from "./storage-diagnosis.js";
export type { StorageSelection, StorageDiagnosticStatus, StorageCandidate, StorageInspection, StorageSandboxDiagnosis, StorageDiagnosis } from "./storage-diagnosis.js";

export type { StorageRecovery, StorageRecoveryOptions, StorageRecoverySelection } from "./storage-recovery.js";

export { configuredContext, Context, LocalContext, RemoteContext, LocalContextBuilder, RemoteContextBuilder, Sandboxes, Volumes, Snapshots, Checkpoints } from "./context.js";
export type { ContextInfo, ComputeType, LocalContextOptions, RemoteContextOptions } from "./context.js";

export type { SandboxConfigInspection, SandboxRuntimeInspection, RemoteSandboxInspection, LocalSandboxInspection, RemoteMountInspection, RemoteSecretInspection } from "./config-inspection.js";
