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
// declare a hand-rolled subset of what the TS layer actually calls so we
// can keep the FFI boundary cleanly typed without introducing a circular
// dependency on the generated d.ts.

export interface NativeBindings {
  readonly Sandbox: NapiSandboxStatic;
  readonly SandboxBuilder: NapiSandboxBuilderCtor;
  readonly Volume: NapiVolumeStatic;
  readonly VolumeBuilder: NapiVolumeBuilderCtor;
  readonly Snapshot: NapiSnapshotStatic;
  readonly SnapshotBuilder: NapiSnapshotBuilderCtor;
  readonly ExecOptionsBuilder: NapiExecOptionsBuilderCtor;
  readonly AttachOptionsBuilder: NapiAttachOptionsBuilderCtor;
  readonly DnsBuilder: NapiBuilderCtor<NapiDnsBuilder>;
  readonly TlsBuilder: NapiBuilderCtor<NapiTlsBuilder>;
  readonly SecretBuilder: NapiBuilderCtor<NapiSecretBuilder>;
  readonly NetworkBuilder: NapiBuilderCtor<NapiNetworkBuilder>;
  readonly NetworkPolicyBuilder: NapiBuilderCtor<NapiNetworkPolicyBuilder>;
  readonly RuleBuilder: NapiBuilderCtor<NapiRuleBuilder>;
  readonly RuleDestinationBuilder: NapiBuilderCtor<NapiRuleDestinationBuilder>;
  readonly InterfaceOverridesBuilder: NapiBuilderCtor<NapiInterfaceOverridesBuilder>;
  readonly PullProgressStream: { prototype: NapiPullProgressStream };
  readonly PullProgressCreate: { prototype: NapiPullProgressCreate };
  readonly MountBuilder: new (guestPath: string) => NapiMountBuilder;
  readonly PatchBuilder: NapiBuilderCtor<NapiPatchBuilder>;
  readonly RegistryConfigBuilder: NapiBuilderCtor<NapiRegistryConfigBuilder>;
  readonly ImageBuilder: NapiBuilderCtor<NapiImageBuilder>;
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

export type NapiBuilderCtor<T> = new () => T;

export interface NapiSandboxStatic {
  start(name: string): Promise<NapiSandbox>;
  startDetached(name: string): Promise<NapiSandbox>;
  get(name: string): Promise<NapiSandboxHandle>;
  list(): Promise<NapiSandboxInfo[]>;
  remove(name: string): Promise<void>;
}

export type NapiSandboxBuilderCtor = new (name: string) => NapiSandboxBuilder;

/** The auto-generated native SandboxBuilder class. Each setter mutates
 * in place and returns `this`; closure-callback sub-builders are typed
 * loosely as `(b: any) => any` here because their full type is the
 * generated one in `native/index.d.ts`. The TS public surface
 * (`Sandbox.builder(...)`) re-types this with the real shapes.
 *
 * Split intentionally into a setters-only base and a terminals
 * interface. The TS-side `SandboxBuilder` (in `src/sandbox.ts`)
 * extends the setters base directly so polymorphic `this` rebinds to
 * the wrapper type through chained calls — `Omit<...> & {...}` would
 * not preserve `this` correctly. */
export interface NapiSandboxBuilderSetters {
  image(s: string): this;
  fromSnapshot(pathOrName: string): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  imageWith(configure: (b: any) => any): this;
  cpus(n: number): this;
  memory(mib: number): this;
  logLevel(level: string): this;
  quietLogs(): this;
  metricsSampleIntervalMs(ms: number): this;
  workdir(path: string): this;
  shell(shell: string): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registry(configure: (b: any) => any): this;
  replace(): this;
  entrypoint(cmd: string[]): this;
  hostname(name: string): this;
  libkrunfwPath(path: string): this;
  user(user: string): this;
  pullPolicy(policy: string): this;
  disableNetwork(): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  network(configure: (b: any) => any): this;
  port(host: number, guest: number): this;
  portUdp(host: number, guest: number): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  secret(configure: (b: any) => any): this;
  secretEnv(envVar: string, value: string, allowedHost: string): this;
  env(key: string, value: string): this;
  envs(vars: Record<string, string>): this;
  rlimit(resource: string, limit: number): this;
  rlimitRange(resource: string, soft: number, hard: number): this;
  script(name: string, content: string): this;
  scripts(scripts: Record<string, string>): this;
  maxDuration(secs: number): this;
  idleTimeout(secs: number): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  volume(guest: string, configure: (b: any) => any): this;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  patch(configure: (b: any) => any): this;
  build(): string;
}

export interface NapiSandboxBuilder extends NapiSandboxBuilderSetters {
  create(): Promise<NapiSandbox>;
  createDetached(): Promise<NapiSandbox>;
  createWithPullProgress(): Promise<NapiPullProgressCreate>;
  createDetachedWithPullProgress(): Promise<NapiPullProgressCreate>;
}

export interface NapiSandbox {
  configJson(): Promise<string>;
  exec(cmd: string, args?: string[]): Promise<NapiExecOutput>;
  execWithBuilder(cmd: string, builder: NapiExecOptionsBuilder): Promise<NapiExecOutput>;
  execStream(cmd: string, args?: string[]): Promise<NapiExecHandle>;
  execStreamWithBuilder(cmd: string, builder: NapiExecOptionsBuilder): Promise<NapiExecHandle>;
  shell(script: string): Promise<NapiExecOutput>;
  shellStream(script: string): Promise<NapiExecHandle>;
  fs(): NapiSandboxFs;
  metrics(): Promise<NapiSandboxMetrics>;
  metricsStream(intervalMs: number): Promise<NapiMetricsStream>;
  attach(cmd: string, args?: string[]): Promise<number>;
  attachWithBuilder(cmd: string, builder: NapiAttachOptionsBuilder): Promise<number>;
  attachShell(): Promise<number>;
  stop(): Promise<void>;
  stopAndWait(): Promise<NapiExitStatus>;
  kill(): Promise<void>;
  drain(): Promise<void>;
  wait(): Promise<NapiExitStatus>;
  detach(): Promise<void>;
  removePersisted(): Promise<void>;
  logs(opts?: LogOptions): Promise<LogEntry[]>;
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
  logs(opts?: LogOptions): Promise<LogEntry[]>;
  snapshot(name: string): Promise<NapiSnapshot>;
  snapshotTo(path: string): Promise<NapiSnapshot>;
}

/** Native shape returned by `Sandbox.logs()` / `SandboxHandle.logs()`. */
export interface LogEntry {
  readonly timestampMs: number;
  readonly source: string;
  readonly sessionId: number | null;
  readonly data: Buffer;
}

/** Native filter object accepted by `logs()`. */
export interface LogOptions {
  tail?: number;
  sinceMs?: number;
  untilMs?: number;
  sources?: string[];
}

export interface NapiSandboxInfo {
  readonly name: string;
  readonly status: string;
  readonly configJson: string;
  readonly createdAt: number | null | undefined;
  readonly updatedAt: number | null | undefined;
}

export interface NapiVolumeStatic {
  get(name: string): Promise<NapiVolumeHandle>;
  list(): Promise<NapiVolumeInfo[]>;
  remove(name: string): Promise<void>;
}

export type NapiVolumeBuilderCtor = new (name: string) => NapiVolumeBuilder;

// Same setters/terminal split as `NapiSandboxBuilder` — see comment
// there for why.
export interface NapiVolumeBuilderSetters {
  quota(mib: number): this;
  label(key: string, value: string): this;
}

export interface NapiVolumeBuilder extends NapiVolumeBuilderSetters {
  create(): Promise<NapiVolume>;
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

export interface NapiVolumeInfo {
  readonly name: string;
  readonly quotaMib: number | null | undefined;
  readonly usedBytes: number;
  readonly labels: Record<string, string>;
  readonly createdAt: number | null | undefined;
}

//-----------------------------------------------------------------------------
// Snapshot
//-----------------------------------------------------------------------------

export interface NapiSnapshotStatic {
  open(pathOrName: string): Promise<NapiSnapshot>;
  get(nameOrDigest: string): Promise<NapiSnapshotHandle>;
  list(): Promise<NapiSnapshotInfo[]>;
  listDir(dir: string): Promise<NapiSnapshot[]>;
  remove(pathOrName: string, opts?: NapiSnapshotRemoveOptions): Promise<void>;
  reindex(dir?: string): Promise<number>;
  export(name: string, out: string, opts?: NapiExportOpts): Promise<void>;
  import(archive: string, dest?: string): Promise<NapiSnapshotHandle>;
}

export type NapiSnapshotBuilderCtor = new (sourceSandbox: string) => NapiSnapshotBuilder;

export interface NapiSnapshotBuilderSetters {
  name(name: string): this;
  path(path: string): this;
  label(key: string, value: string): this;
  force(): this;
  recordIntegrity(): this;
}

export interface NapiSnapshotBuilder extends NapiSnapshotBuilderSetters {
  create(): Promise<NapiSnapshot>;
}

export interface NapiSnapshot {
  readonly path: string;
  readonly digest: string;
  readonly sizeBytes: bigint;
  readonly imageRef: string;
  readonly imageManifestDigest: string;
  readonly format: string; // "raw" | "qcow2"
  readonly fstype: string;
  readonly parent: string | null | undefined;
  readonly createdAt: string; // RFC 3339 UTC
  readonly labels: Record<string, string>;
  readonly sourceSandbox: string | null | undefined;
  verify(): Promise<NapiSnapshotVerifyReport>;
}

export interface NapiSnapshotHandle {
  readonly digest: string;
  readonly name: string | null | undefined;
  readonly parentDigest: string | null | undefined;
  readonly imageRef: string;
  readonly format: string;
  readonly sizeBytes: bigint | null | undefined;
  readonly createdAt: number;
  readonly path: string;
  open(): Promise<NapiSnapshot>;
  remove(opts?: NapiSnapshotRemoveOptions): Promise<void>;
}

export interface NapiSnapshotInfo {
  readonly digest: string;
  readonly name: string | null | undefined;
  readonly parentDigest: string | null | undefined;
  readonly imageRef: string;
  readonly format: string;
  readonly sizeBytes: number | null | undefined;
  readonly createdAt: number;
  readonly path: string;
}

export interface NapiExportOpts {
  withParents?: boolean;
  withImage?: boolean;
  plainTar?: boolean;
}

export interface NapiSnapshotRemoveOptions {
  force?: boolean;
}

export interface NapiSnapshotVerifyReport {
  readonly digest: string;
  readonly path: string;
  readonly upperKind: string; // "notRecorded" | "verified"
  readonly upperAlgorithm: string | null | undefined;
  readonly upperDigest: string | null | undefined;
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

export interface NapiExecHandle extends AsyncIterable<NapiExecEvent> {
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

// Builder classes — opaque from the TS layer's POV. Setters return
// `this`. The full method shapes are in `native/index.d.ts`; we use
// loose typing here to keep this file decoupled from the generated d.ts.

export type NapiExecOptionsBuilderCtor = new () => NapiExecOptionsBuilder;
export interface NapiExecOptionsBuilder {
  arg(arg: string): this;
  args(args: string[]): this;
  cwd(cwd: string): this;
  user(user: string): this;
  env(key: string, value: string): this;
  envs(vars: Record<string, string>): this;
  timeout(ms: number): this;
  stdinNull(): this;
  stdinPipe(): this;
  stdinBytes(data: Buffer): this;
  tty(enabled: boolean): this;
  rlimit(resource: string, limit: number): this;
  rlimitRange(resource: string, soft: number, hard: number): this;
}

export type NapiAttachOptionsBuilderCtor = new () => NapiAttachOptionsBuilder;
export interface NapiAttachOptionsBuilder {
  arg(arg: string): this;
  args(args: string[]): this;
  cwd(cwd: string): this;
  user(user: string): this;
  env(key: string, value: string): this;
  envs(vars: Record<string, string>): this;
  detachKeys(spec: string): this;
  rlimit(resource: string, limit: number): this;
  rlimitRange(resource: string, soft: number, hard: number): this;
}

export interface NapiDnsBuilder {
  rebindProtection(enabled: boolean): this;
  nameservers(servers: string[]): this;
  queryTimeoutMs(ms: number): this;
  build(): NapiDnsConfig;
}

export interface NapiDnsConfig {
  readonly rebindProtection: boolean;
  readonly nameservers: string[];
  readonly queryTimeoutMs: number;
}

export interface NapiTlsBuilder {
  bypass(pattern: string): this;
  verifyUpstream(verify: boolean): this;
  interceptedPorts(ports: number[]): this;
  blockQuic(block: boolean): this;
  upstreamCaCert(path: string): this;
  interceptCaCert(path: string): this;
  interceptCaKey(path: string): this;
  build(): NapiTlsConfig;
}

export interface NapiTlsConfig {
  readonly enabled: boolean;
  readonly bypass: string[];
  readonly verifyUpstream: boolean;
  readonly interceptedPorts: number[];
  readonly blockQuic: boolean;
  readonly upstreamCaCertPaths: string[];
  readonly interceptCaCertPath: string | null;
  readonly interceptCaKeyPath: string | null;
}

export interface NapiSecretBuilder {
  env(varName: string): this;
  value(value: string): this;
  placeholder(placeholder: string): this;
  allowHost(host: string): this;
  allowHostPattern(pattern: string): this;
  allowAnyHostDangerous(iUnderstand: boolean): this;
  requireTlsIdentity(enabled: boolean): this;
  injectHeaders(enabled: boolean): this;
  injectBasicAuth(enabled: boolean): this;
  injectQuery(enabled: boolean): this;
  injectBody(enabled: boolean): this;
  build(): NapiSecretEntry;
}

export interface NapiSecretEntry {
  readonly envVar: string;
  readonly value: string;
  readonly placeholder: string;
  readonly allowedHosts: string[];
  readonly allowedHostPatterns: string[];
  readonly allowAnyHost: boolean;
  readonly requireTlsIdentity: boolean;
  readonly injection: NapiSecretInjection;
}

export interface NapiSecretInjection {
  readonly headers: boolean;
  readonly basicAuth: boolean;
  readonly queryParams: boolean;
  readonly body: boolean;
}

export interface NapiNetworkBuilder {
  enabled(enabled: boolean): this;
  port(host: number, guest: number): this;
  portUdp(host: number, guest: number): this;
  policyJson(json: string): this;
  policyFromBuilder(builder: NapiNetworkPolicyBuilder): this;
  dns(configure: (b: NapiDnsBuilder) => NapiDnsBuilder): this;
  tls(configure: (b: NapiTlsBuilder) => NapiTlsBuilder): this;
  secret(configure: (b: NapiSecretBuilder) => NapiSecretBuilder): this;
  secretEnv(envVar: string, value: string, placeholder: string, allowedHost: string): this;
  secretEnvSimple(envVar: string, value: string, allowedHost: string): this;
  interface(
    configure: (b: NapiInterfaceOverridesBuilder) => NapiInterfaceOverridesBuilder,
  ): this;
  onSecretViolation(action: string): this;
  maxConnections(max: number): this;
  trustHostCAs(enabled: boolean): this;
}

export interface NapiInterfaceOverridesBuilder {
  mac(mac: string): this;
  mtu(mtu: number): this;
  ipv4(address: string): this;
  ipv6(address: string): this;
}

export interface NapiPullProgressEvent {
  readonly kind: string;
  readonly reference?: string;
  readonly manifestDigest?: string;
  readonly layerCount?: number;
  readonly totalDownloadBytes?: number;
  readonly layerIndex?: number;
  readonly digest?: string;
  readonly diffId?: string;
  readonly downloadedBytes?: number;
  readonly totalBytes?: number;
  readonly bytesRead?: number;
}

export interface NapiPullProgressStream extends AsyncIterable<NapiPullProgressEvent> {
  recv(): Promise<NapiPullProgressEvent | null>;
}

export interface NapiPullProgressCreate {
  readonly progress: NapiPullProgressStream;
  awaitSandbox(): Promise<NapiSandbox>;
}

export interface NapiNetworkPolicyBuilder {
  defaultAllow(): this;
  defaultDeny(): this;
  defaultEgress(action: string): this;
  defaultIngress(action: string): this;
  rule(configure: (rb: NapiRuleBuilder) => NapiRuleBuilder): this;
  egress(configure: (rb: NapiRuleBuilder) => NapiRuleBuilder): this;
  ingress(configure: (rb: NapiRuleBuilder) => NapiRuleBuilder): this;
  any(configure: (rb: NapiRuleBuilder) => NapiRuleBuilder): this;
  build(): NapiBuiltNetworkPolicy;
}

export interface NapiRuleBuilder {
  egress(): this;
  ingress(): this;
  any(): this;
  tcp(): this;
  udp(): this;
  icmpv4(): this;
  icmpv6(): this;
  port(port: number): this;
  portRange(lo: number, hi: number): this;
  ports(ports: number[]): this;
  allowPublic(): this;
  denyPublic(): this;
  allowPrivate(): this;
  denyPrivate(): this;
  allowLoopback(): this;
  denyLoopback(): this;
  allowLinkLocal(): this;
  denyLinkLocal(): this;
  allowMeta(): this;
  denyMeta(): this;
  allowMulticast(): this;
  denyMulticast(): this;
  allowHost(): this;
  denyHost(): this;
  allowLocal(): this;
  denyLocal(): this;
  allowDomain(name: string): this;
  denyDomain(name: string): this;
  allowDomains(names: string[]): this;
  denyDomains(names: string[]): this;
  allowDomainSuffix(suffix: string): this;
  denyDomainSuffix(suffix: string): this;
  allowDomainSuffixes(suffixes: string[]): this;
  denyDomainSuffixes(suffixes: string[]): this;
  allow(configure: (d: NapiRuleDestinationBuilder) => NapiRuleDestinationBuilder): this;
  deny(configure: (d: NapiRuleDestinationBuilder) => NapiRuleDestinationBuilder): this;
}

export interface NapiRuleDestinationBuilder {
  ip(ip: string): this;
  cidr(cidr: string): this;
  domain(domain: string): this;
  domainSuffix(suffix: string): this;
  group(group: string): this;
  any(): this;
}

export interface NapiBuiltNetworkPolicy {
  readonly defaultEgress: string;
  readonly defaultIngress: string;
  readonly rules: readonly NapiBuiltNetworkPolicyRule[];
}

export interface NapiBuiltNetworkPolicyRule {
  readonly direction: string;
  readonly destination: NapiBuiltNetworkPolicyDestination;
  readonly protocols: readonly string[];
  readonly ports: readonly { readonly start: number; readonly end: number }[];
  readonly action: string;
}

export interface NapiBuiltNetworkPolicyDestination {
  readonly kind: string;
  readonly cidr?: string;
  readonly domain?: string;
  readonly suffix?: string;
  readonly group?: string;
}

export interface NapiMountBuilder {
  bind(host: string): this;
  named(name: string): this;
  tmpfs(): this;
  disk(host: string): this;
  format(format: string): this;
  fstype(fstype: string): this;
  readonly(): this;
  size(mib: number): this;
}

export interface NapiPatchBuilder {
  text(path: string, content: string, opts?: { mode?: number; replace?: boolean }): this;
  file(path: string, content: Buffer, opts?: { mode?: number; replace?: boolean }): this;
  copyFile(src: string, dst: string, opts?: { mode?: number; replace?: boolean }): this;
  copyDir(src: string, dst: string, opts?: { replace?: boolean }): this;
  symlink(target: string, link: string, opts?: { replace?: boolean }): this;
  mkdir(path: string, opts?: { mode?: number }): this;
  remove(path: string): this;
  append(path: string, content: string): this;
  build(): NapiBuiltPatch[];
}

export interface NapiBuiltPatch {
  readonly kind: string;
  readonly path?: string;
  readonly src?: string;
  readonly dst?: string;
  readonly target?: string;
  readonly link?: string;
  readonly content?: string;
  readonly contentBytes?: Buffer;
  readonly mode?: number;
  readonly replace?: boolean;
}

export interface NapiRegistryConfigBuilder {
  auth(auth: { kind: string; username?: string; password?: string }): this;
  insecure(): this;
  caCerts(pem: Buffer): this;
}

export interface NapiImageBuilder {
  disk(path: string): this;
  fstype(fstype: string): this;
}
