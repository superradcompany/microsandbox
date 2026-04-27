import { createRequire } from "node:module";
import { msbPath } from "./resolve-binary.js";

// Make the bundled msb visible to the Rust binding. `MSB_PATH` is the
// hook the SDK's config layer honors first; libkrunfw is then resolved
// alongside msb (msb_dir/../lib/libkrunfw.{so,dylib}). Set only when
// unset so user-provided overrides win.
if (!process.env.MSB_PATH) {
  const resolved = msbPath();
  if (resolved) process.env.MSB_PATH = resolved;
}

const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const native = require("../../native/index.cjs") as NativeBindings;

export const napi = native;

// The native binding's true types are emitted into native/index.d.ts. We
// don't import them directly to keep the TS surface independent of the
// generated names; this hand-rolled subset documents what we actually call.
export interface NativeBindings {
  readonly Sandbox: NapiSandboxStatic;
  readonly Volume: NapiVolumeStatic;
  readonly Setup: new () => NapiSetup;
  readonly imageGet: (reference: string) => Promise<NapiImageHandle>;
  readonly imageList: () => Promise<NapiImageInfo[]>;
  readonly imageInspect: (reference: string) => Promise<NapiImageDetail>;
  readonly imageRemove: (reference: string, force?: boolean) => Promise<void>;
  readonly imageGcLayers: () => Promise<number>;
  readonly imageGc: () => Promise<number>;
  readonly install: () => Promise<void>;
  readonly isInstalled: () => boolean;
  readonly allSandboxMetrics: () => Promise<Record<string, NapiSandboxMetrics>>;
}

export interface NapiSandboxStatic {
  create(config: NapiSandboxConfig): Promise<NapiSandbox>;
  createDetached(config: NapiSandboxConfig): Promise<NapiSandbox>;
  start(name: string): Promise<NapiSandbox>;
  startDetached(name: string): Promise<NapiSandbox>;
  get(name: string): Promise<NapiSandboxHandle>;
  list(): Promise<NapiSandboxInfo[]>;
  remove(name: string): Promise<void>;
}

export interface NapiSandbox {
  readonly name: Promise<string>;
  readonly ownsLifecycle: Promise<boolean>;
  exec(cmd: string, args?: string[]): Promise<NapiExecOutput>;
  execWithConfig(config: NapiExecConfig): Promise<NapiExecOutput>;
  execStream(cmd: string, args?: string[]): Promise<NapiExecHandle>;
  execStreamWithConfig(config: NapiExecConfig): Promise<NapiExecHandle>;
  shell(script: string): Promise<NapiExecOutput>;
  shellStream(script: string): Promise<NapiExecHandle>;
  fs(): NapiSandboxFs;
  metrics(): Promise<NapiSandboxMetrics>;
  metricsStream(intervalMs: number): Promise<NapiMetricsStream>;
  attach(cmd: string, args?: string[]): Promise<number>;
  attachWithConfig(config: NapiAttachConfig): Promise<number>;
  attachShell(): Promise<number>;
  stop(): Promise<void>;
  stopAndWait(): Promise<NapiExitStatus>;
  kill(): Promise<void>;
  drain(): Promise<void>;
  wait(): Promise<NapiExitStatus>;
  detach(): Promise<void>;
  removePersisted(): Promise<void>;
}

export interface NapiSandboxHandle {
  readonly name: string;
  readonly status: string;
  readonly configJson: string;
  readonly createdAt: number | null;
  readonly updatedAt: number | null;
  metrics(): Promise<NapiSandboxMetrics>;
  start(): Promise<NapiSandbox>;
  startDetached(): Promise<NapiSandbox>;
  connect(): Promise<NapiSandbox>;
  stop(): Promise<void>;
  kill(): Promise<void>;
  remove(): Promise<void>;
}

export interface NapiSandboxInfo {
  readonly name: string;
  readonly status: string;
  readonly configJson: string;
  readonly createdAt: number | null | undefined;
  readonly updatedAt: number | null | undefined;
}

export interface NapiVolumeStatic {
  create(config: NapiVolumeConfig): Promise<NapiVolume>;
  get(name: string): Promise<NapiVolumeHandle>;
  list(): Promise<NapiVolumeInfo[]>;
  remove(name: string): Promise<void>;
}

export interface NapiVolume {
  readonly name: string;
  readonly path: string;
  fs(): NapiVolumeFs;
}

export interface NapiVolumeHandle {
  readonly name: string;
  readonly quotaMib: number | null | undefined;
  readonly usedBytes: number;
  readonly labels: Record<string, string>;
  readonly createdAt: number | null | undefined;
  fs(): NapiVolumeFs;
  remove(): Promise<void>;
}

export interface NapiVolumeFs {
  read(path: string): Promise<Buffer>;
  readString(path: string): Promise<string>;
  readStream(path: string): Promise<NapiVolumeFsReadStream>;
  write(path: string, data: Buffer): Promise<void>;
  writeStream(path: string): Promise<NapiVolumeFsWriteSink>;
  list(path: string): Promise<NapiFsEntry[]>;
  mkdir(path: string): Promise<void>;
  removeDir(path: string): Promise<void>;
  remove(path: string): Promise<void>;
  copy(from: string, to: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  stat(path: string): Promise<NapiFsMetadata>;
  exists(path: string): Promise<boolean>;
}

export interface NapiVolumeFsReadStream extends AsyncIterable<Buffer> {
  recv(): Promise<Buffer | null>;
}

export interface NapiVolumeFsWriteSink {
  write(data: Buffer): Promise<void>;
  close(): Promise<void>;
}

export interface NapiImageHandle {
  readonly reference: string;
  readonly sizeBytes: number | null | undefined;
  readonly manifestDigest: string | null | undefined;
  readonly architecture: string | null | undefined;
  readonly os: string | null | undefined;
  readonly layerCount: number;
  readonly lastUsedAt: number | null | undefined;
  readonly createdAt: number | null | undefined;
}

export interface NapiImageInfo {
  readonly reference: string;
  readonly manifestDigest: string | null | undefined;
  readonly architecture: string | null | undefined;
  readonly os: string | null | undefined;
  readonly layerCount: number;
  readonly sizeBytes: number | null | undefined;
  readonly createdAt: number | null | undefined;
  readonly lastUsedAt: number | null | undefined;
}

export interface NapiImageConfigDetail {
  readonly digest: string;
  readonly env: string[];
  readonly cmd: string[] | null | undefined;
  readonly entrypoint: string[] | null | undefined;
  readonly workingDir: string | null | undefined;
  readonly user: string | null | undefined;
  readonly labelsJson: string | null | undefined;
  readonly stopSignal: string | null | undefined;
}

export interface NapiImageLayerDetail {
  readonly diffId: string;
  readonly blobDigest: string;
  readonly mediaType: string | null | undefined;
  readonly compressedSizeBytes: number | null | undefined;
  readonly erofsSizeBytes: number | null | undefined;
  readonly position: number;
}

export interface NapiImageDetail extends NapiImageInfo {
  readonly config: NapiImageConfigDetail | null | undefined;
  readonly layers: NapiImageLayerDetail[];
}

export interface NapiSetup {
  baseDir(path: string): NapiSetup;
  version(version: string): NapiSetup;
  skipVerify(enabled: boolean): NapiSetup;
  force(enabled: boolean): NapiSetup;
  install(): Promise<void>;
}

export interface NapiVolumeInfo {
  readonly name: string;
  readonly quotaMib: number | null | undefined;
  readonly usedBytes: number;
  readonly labels: Record<string, string>;
  readonly createdAt: number | null | undefined;
}

export interface NapiExecHandle extends AsyncIterable<NapiSandboxMetrics> {
  readonly id: Promise<string>;
  recv(): Promise<NapiExecEvent | null>;
  takeStdin(): Promise<NapiExecSink | null>;
  wait(): Promise<NapiExitStatus>;
  collect(): Promise<NapiExecOutput>;
  signal(signal: number): Promise<void>;
  kill(): Promise<void>;
}

export interface NapiExecOutput {
  readonly code: number;
  readonly success: boolean;
  stdout(): string;
  stderr(): string;
  stdoutBytes(): Buffer;
  stderrBytes(): Buffer;
  status(): NapiExitStatus;
}

export interface NapiExecSink {
  write(data: Buffer): Promise<void>;
  close(): Promise<void>;
}

export interface NapiExecEvent {
  readonly eventType: "started" | "stdout" | "stderr" | "exited";
  readonly pid?: number;
  readonly data?: Buffer;
  readonly code?: number;
}

export interface NapiExitStatus {
  readonly code: number;
  readonly success: boolean;
}

export interface NapiSandboxFs {
  read(path: string): Promise<Buffer>;
  readString(path: string): Promise<string>;
  write(path: string, data: Buffer): Promise<void>;
  list(path: string): Promise<NapiFsEntry[]>;
  mkdir(path: string): Promise<void>;
  removeDir(path: string): Promise<void>;
  remove(path: string): Promise<void>;
  copy(from: string, to: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  stat(path: string): Promise<NapiFsMetadata>;
  exists(path: string): Promise<boolean>;
  copyFromHost(hostPath: string, guestPath: string): Promise<void>;
  copyToHost(guestPath: string, hostPath: string): Promise<void>;
  readStream(path: string): Promise<NapiFsReadStream>;
  writeStream(path: string): Promise<NapiFsWriteSink>;
}

export interface NapiFsReadStream extends AsyncIterable<Buffer> {
  recv(): Promise<Buffer | null>;
}

export interface NapiFsWriteSink {
  write(data: Buffer): Promise<void>;
  close(): Promise<void>;
}

export interface NapiFsEntry {
  readonly path: string;
  readonly kind: string;
  readonly size: number;
  readonly mode: number;
  readonly modified?: number;
}

export interface NapiFsMetadata {
  readonly kind: string;
  readonly size: number;
  readonly mode: number;
  readonly readonly: boolean;
  readonly modified?: number;
  readonly created?: number;
}

export interface NapiSandboxMetrics {
  readonly cpuPercent: number;
  readonly memoryBytes: number;
  readonly memoryLimitBytes: number;
  readonly diskReadBytes: number;
  readonly diskWriteBytes: number;
  readonly netRxBytes: number;
  readonly netTxBytes: number;
  readonly uptimeMs: number;
  readonly timestampMs: number;
}

export interface NapiMetricsStream extends AsyncIterable<NapiSandboxMetrics> {
  recv(): Promise<NapiSandboxMetrics | null>;
}

export interface NapiSandboxConfig {
  name: string;
  image: string;
  memoryMib?: number;
  cpus?: number;
  workdir?: string;
  shell?: string;
  entrypoint?: string[];
  cmd?: string[];
  hostname?: string;
  libkrunfwPath?: string;
  user?: string;
  env?: Record<string, string>;
  scripts?: Record<string, string>;
  volumes?: Record<string, NapiMountConfig>;
  patches?: NapiPatchConfig[];
  pullPolicy?: string;
  logLevel?: string;
  replace?: boolean;
  quietLogs?: boolean;
  labels?: Record<string, string>;
  stopSignal?: string;
  maxDurationSecs?: number;
  registry?: NapiRegistryConfig;
  ports?: Record<string, number>;
  network?: NapiNetworkConfig;
  secrets?: NapiSecretEntry[];
}

export interface NapiMountConfig {
  bind?: string;
  named?: string;
  tmpfs?: boolean;
  disk?: string;
  format?: "qcow2" | "raw" | "vmdk";
  fstype?: string;
  readonly?: boolean;
  sizeMib?: number;
}

export interface NapiPatchConfig {
  kind: string;
  path?: string;
  content?: string;
  src?: string;
  dst?: string;
  target?: string;
  link?: string;
  mode?: number;
  replace?: boolean;
}

export interface NapiRegistryConfig {
  auth?: { username: string; password: string };
  insecure?: boolean;
  caCertsPath?: string;
}

export interface NapiNetworkConfig {
  policy?: string;
  rules?: NapiPolicyRule[];
  defaultEgress?: string;
  defaultIngress?: string;
  dns?: NapiDnsConfig;
  tls?: NapiTlsConfig;
  maxConnections?: number;
  trustHostCas?: boolean;
}

export interface NapiPolicyRule {
  action: string;
  direction?: string;
  destination?: string;
  protocol?: string;
  protocols?: string[];
  port?: string;
  ports?: string[];
}

export interface NapiDnsConfig {
  blockDomains?: string[];
  blockDomainSuffixes?: string[];
  rebindProtection?: boolean;
  nameservers?: string[];
  queryTimeoutMs?: number;
}

export interface NapiTlsConfig {
  bypass?: string[];
  verifyUpstream?: boolean;
  interceptedPorts?: number[];
  blockQuic?: boolean;
  interceptCaCert?: string;
  interceptCaKey?: string;
  upstreamCaCert?: string[];
}

export interface NapiSecretEntry {
  envVar: string;
  value: string;
  allowHosts?: string[];
  allowHostPatterns?: string[];
  placeholder?: string;
  requireTls?: boolean;
  onViolation?: string;
  inject?: NapiSecretInjection;
}

export interface NapiSecretInjection {
  headers?: boolean;
  basicAuth?: boolean;
  queryParams?: boolean;
  body?: boolean;
}

export interface NapiExecConfig {
  cmd: string;
  args?: string[];
  cwd?: string;
  user?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  stdin?: string;
  tty?: boolean;
}

export interface NapiAttachConfig {
  cmd: string;
  args?: string[];
  cwd?: string;
  user?: string;
  env?: Record<string, string>;
  detachKeys?: string;
}

export interface NapiVolumeConfig {
  name: string;
  quotaMib?: number;
  labels?: Record<string, string>;
}
