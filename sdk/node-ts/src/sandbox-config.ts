import type { LogLevel } from "./log-level.js";
import type { Patch } from "./patch.js";
import type { PullPolicy } from "./pull-policy.js";
import type { RootfsSource } from "./rootfs.js";
import type { VolumeMount } from "./mount.js";
import type { NetworkConfig, SecretEntry } from "./network-config.js";
import type { RegistryConfig } from "./registry-config-builder.js";

/** Built sandbox configuration produced by `SandboxBuilder.build()`. */
export interface SandboxConfig {
  readonly name: string;
  readonly image: RootfsSource;
  readonly cpus: number | null;
  readonly memoryMib: number | null;
  readonly logLevel: LogLevel | null;
  readonly quietLogs: boolean;
  readonly workdir: string | null;
  readonly shell: string | null;
  readonly entrypoint: readonly string[] | null;
  readonly cmd: readonly string[] | null;
  readonly hostname: string | null;
  readonly user: string | null;
  readonly libkrunfwPath: string | null;
  readonly env: ReadonlyArray<readonly [string, string]>;
  readonly scripts: ReadonlyArray<readonly [string, string]>;
  readonly mounts: readonly VolumeMount[];
  readonly patches: readonly Patch[];
  readonly pullPolicy: PullPolicy | null;
  readonly replace: boolean;
  readonly maxDurationSecs: number | null;
  readonly idleTimeoutSecs: number | null;
  readonly portsTcp: ReadonlyArray<readonly [number, number]>;
  readonly portsUdp: ReadonlyArray<readonly [number, number]>;
  readonly registry: RegistryConfig | null;
  readonly network: NetworkConfig | null;
  readonly disableNetwork: boolean;
  readonly secrets: readonly SecretEntry[];
}
