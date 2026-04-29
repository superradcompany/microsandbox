import { mapNapiError } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";

// Sandbox lifecycle and execution
export { Sandbox } from "./sandbox.js";
import { Sandbox as _Sandbox, type SandboxBuilder as _SBT } from "./sandbox.js";
/**
 * Native fluent builder for a sandbox. `new SandboxBuilder(name)` is
 * equivalent to `Sandbox.builder(name)` — both return the same shape
 * with `.create()` resolving to a TS `Sandbox`.
 */
export const SandboxBuilder = function SandboxBuilder(
  this: unknown,
  name: string,
) {
  return _Sandbox.builder(name);
} as unknown as new (name: string) => _SBT;
export type SandboxBuilder = _SBT;
export { SandboxHandle } from "./sandbox-handle.js";
export { ExecHandle, ExecOutput, ExecSink } from "./exec.js";

// Filesystem
export { FsReadStream, FsWriteSink, SandboxFs } from "./fs.js";

// Volumes
export { Volume } from "./volume.js";
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

// Native fluent builders. The classes themselves live in the napi-rs
// binding (`native/index.cjs`); the TS layer just re-exports them so
// `import { DnsBuilder } from "microsandbox"` keeps working.

// Attach a JS-side `policy(NetworkPolicy)` method to the native
// `NetworkBuilder.prototype` so callers can pass the plain
// `NetworkPolicy` object produced by `NetworkPolicy.publicOnly()` /
// `.allowAll()` / `.none()` / `.nonLocal()` and the custom-rule
// factories. Native exposes `policyJson(string)`; this shim
// serializes once.
// Wrap a class's prototype method so any thrown error gets remapped
// to a typed `MicrosandboxError` subclass via the prefix the Rust
// binding emits (`[InvalidConfig] ...`). Used on builders whose
// `.build()` can throw a typed validation error.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function wrapMethodWithErrorMap(cls: any, method: string) {
  const proto = cls.prototype;
  const orig = proto[method];
  if (typeof orig !== "function" || (orig as { __wrapped?: boolean }).__wrapped) {
    return;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wrapped = function (this: unknown, ...args: any[]) {
    try {
      const result = orig.apply(this, args);
      if (result && typeof result.then === "function") {
        return result.catch((e: unknown) => {
          throw mapNapiError(e);
        });
      }
      return result;
    } catch (e) {
      throw mapNapiError(e);
    }
  };
  (wrapped as { __wrapped?: boolean }).__wrapped = true;
  proto[method] = wrapped;
}

wrapMethodWithErrorMap(napi.MountBuilder, "build");
wrapMethodWithErrorMap(napi.SandboxBuilder, "create");
wrapMethodWithErrorMap(napi.SandboxBuilder, "createDetached");
wrapMethodWithErrorMap(napi.PatchBuilder, "build");
wrapMethodWithErrorMap(napi.DnsBuilder, "build");
wrapMethodWithErrorMap(napi.SecretBuilder, "build");
wrapMethodWithErrorMap(napi.VolumeBuilder, "create");

// `SandboxBuilder.build()` natively returns the JSON-serialized config
// (snake_case). Replace it with a TS-side wrapper that parses and
// key-maps to camelCase so consumers get a plain JS object.
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto: any = napi.SandboxBuilder.prototype;
  if (!proto.__buildWrapped) {
    const origBuild = proto.build;
    const snakeToCamel = (k: string): string =>
      k.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const remapKeys = (v: any): any => {
      if (Array.isArray(v)) return v.map(remapKeys);
      if (v && typeof v === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v)) out[snakeToCamel(k)] = remapKeys(val);
        return out;
      }
      return v;
    };
    proto.build = function () {
      let json: string;
      try {
        json = origBuild.apply(this);
      } catch (e) {
        throw mapNapiError(e);
      }
      return remapKeys(JSON.parse(json));
    };
    proto.__buildWrapped = true;
  }
}

{
  // The TS-side `NetworkPolicy` object uses camelCase (`defaultEgress`,
  // `defaultIngress`); the Rust struct it deserializes into expects
  // snake_case. Convert known top-level keys before serializing.
  const camelToSnake = (k: string): string =>
    k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const remapKeys = (v: any): any => {
    if (Array.isArray(v)) return v.map(remapKeys);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) out[camelToSnake(k)] = remapKeys(val);
      return out;
    }
    return v;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto: any = napi.NetworkBuilder.prototype;
  if (!proto.policy) {
    proto.policy = function (p: unknown) {
      this.policyJson(JSON.stringify(remapKeys(p)));
      return this;
    };
  }
}

export const DnsBuilder = napi.DnsBuilder;
export const TlsBuilder = napi.TlsBuilder;
export const SecretBuilder = napi.SecretBuilder;
export const NetworkBuilder = napi.NetworkBuilder;
export const MountBuilder = napi.MountBuilder;
export const PatchBuilder = napi.PatchBuilder;
export const RegistryConfigBuilder = napi.RegistryConfigBuilder;
export const ImageBuilder = napi.ImageBuilder;
export const ExecOptionsBuilder = napi.ExecOptionsBuilder;
export const AttachOptionsBuilder = napi.AttachOptionsBuilder;

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
export { VolumeMountKinds } from "./mount.js";
export type { VolumeMount, VolumeMountKind } from "./mount.js";
export { PatchKinds } from "./patch.js";
export type { Patch, PatchKind } from "./patch.js";
export { RegistryAuthKinds } from "./registry.js";
export type { RegistryAuth, RegistryAuthKind } from "./registry.js";

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
