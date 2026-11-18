import type { LogLevel } from "./log-level.js";
import type { PullPolicy } from "./pull-policy.js";

/** A fresh persisted observation. It is not a creation request or applied VM state. */
export interface SandboxRuntimeInspection {
  workdir: string | null;
  shell: string | null;
  scripts: Record<string, string>;
  entrypoint: string[] | null;
  cmd: string[] | null;
  hostname: string | null;
  user: string | null;
  logLevel: LogLevel | null;
  metricsSampleIntervalMs: number | null;
  disableMetricsSample: boolean;
  guestClock?: "sync" | "off" | null;
}

/** A projected mount exposes presentation only, never a host path or volume ID. */
export type RemoteMountInspection = {
  guest: string;
  options: { readonly: boolean; noexec: boolean; nosuid: boolean; nodev: boolean; overrideUid?: number | null; overrideGid?: number | null };
} & (
  | { type: "Bind"; statVirtualization: string; hostPermissions: string; quotaMib: number | null }
  | { type: "Named"; statVirtualization: string; hostPermissions: string }
  | { type: "Tmpfs"; sizeMib: number | null }
  | { type: "DiskImage"; format: string; fstype: string | null }
);

export interface RemoteSecretInspection {
  envVar: string;
  placeholder: string;
  allowedHosts: Array<"any" | { exact: string } | { wildcard: string }>;
  injection: { headers: boolean; basicAuth: boolean; queryParams: boolean; body: boolean };
  onViolation: "block" | "block_and_log" | "block_and_terminate" |
    { passthrough: RemoteSecretInspection["allowedHosts"] } | null;
}

export interface RemoteSandboxInspection {
  /** null means a non-OCI source whose details are unavailable in this response. */
  image: string | null;
  resources: { vcpus: number; memoryMib: number; diskSizeMib?: number | null };
  runtime: SandboxRuntimeInspection;
  env: Array<{ key: string; value: string }>;
  labels: Record<string, string>;
  rlimits: Array<{ resource: string; soft: number; hard: number }>;
  lifecycle: { ephemeral: boolean; maxDurationSecs?: number | null; idleTimeoutSecs?: number | null };
  mounts: RemoteMountInspection[];
  network: {
    enabled: boolean;
    ports: Array<{ hostPort: number; guestPort: number; protocol: "tcp" | "udp"; hostBind: string }>;
    trustHostCas: boolean;
    maxConnections: number | null;
    interface: Record<string, unknown> | null;
    policy: Record<string, unknown> | null;
    dns: Record<string, unknown> | null;
    tls: Record<string, unknown> | null;
    secrets: RemoteSecretInspection[];
  };
}

/** Local persisted spec. Backend-specific nested settings retain their native JSON shape. */
export interface LocalSandboxInspection extends Record<string, unknown> {
  name: string;
  image: Record<string, unknown>;
  pullPolicy: PullPolicy;
  resources: { cpus: number; memoryMib: number; [key: string]: unknown };
  runtime: SandboxRuntimeInspection;
  env: Array<{ key: string; value: string }>;
  labels: Record<string, string>;
}

/** Paths use Rust/wire snake_case even in SDKs that camel-case object keys. */
export type SandboxConfigInspection = {
  name: string;
  unavailable: string[];
  redacted: string[];
} & (
  | { kind: "local"; spec: LocalSandboxInspection }
  | { kind: "remote"; spec: RemoteSandboxInspection }
);
