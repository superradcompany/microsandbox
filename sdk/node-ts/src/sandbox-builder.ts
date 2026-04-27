import { InvalidConfigError } from "./errors.js";
import type { LogLevel } from "./log-level.js";
import { intoRootfsSource } from "./rootfs.js";
import type { RootfsSource } from "./rootfs.js";
import type { PullPolicy } from "./pull-policy.js";
import type { Mebibytes } from "./size.js";
import { MountBuilder } from "./mount-builder.js";
import type { VolumeMount } from "./mount.js";
import { PatchBuilder } from "./patch-builder.js";
import type { Patch } from "./patch.js";
import { RegistryConfigBuilder } from "./registry-config-builder.js";
import type { RegistryConfig } from "./registry-config-builder.js";
import { NetworkBuilder } from "./network-builder.js";
import type { NetworkConfig, SecretEntry } from "./network-config.js";
import { SecretBuilder } from "./secret-builder.js";
import type { SandboxConfig } from "./sandbox-config.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import {
  mountToNapi,
  networkConfigToNapi,
  patchToNapi,
  registryAuthToNapi,
  secretEntryToNapi,
} from "./internal/marshal.js";
import { napi } from "./internal/napi.js";
import type { NapiSandboxConfig } from "./internal/napi.js";
import { Sandbox } from "./sandbox.js";

export class SandboxBuilder {
  private readonly _name: string;
  private _image: RootfsSource | null = null;
  private _cpus: number | null = null;
  private _memoryMib: number | null = null;
  private _logLevel: LogLevel | null = null;
  private _quietLogs = false;
  private _workdir: string | null = null;
  private _shell: string | null = null;
  private _entrypoint: string[] | null = null;
  private _cmd: string[] | null = null;
  private _hostname: string | null = null;
  private _user: string | null = null;
  private _libkrunfwPath: string | null = null;
  private _env: Array<readonly [string, string]> = [];
  private _scripts: Array<readonly [string, string]> = [];
  private _mounts: VolumeMount[] = [];
  private _patches: Patch[] = [];
  private _pullPolicy: PullPolicy | null = null;
  private _replace = false;
  private _maxDuration: number | null = null;
  private _idleTimeout: number | null = null;
  private _portsTcp: Array<readonly [number, number]> = [];
  private _portsUdp: Array<readonly [number, number]> = [];
  private _registry: RegistryConfig | null = null;
  private _network: NetworkConfig | null = null;
  private _disableNetwork = false;
  private _topLevelSecrets: SecretEntry[] = [];
  private _deferredError: Error | null = null;

  /** @internal use `Sandbox.builder(name)` */
  constructor(name: string) {
    this._name = name;
  }

  // -- core image / sizing -----------------------------------------------

  image(src: string | RootfsSource): this {
    try {
      this._image = intoRootfsSource(src);
    } catch (e) {
      this._deferredError ??= e instanceof Error ? e : new Error(String(e));
    }
    return this;
  }

  cpus(count: number): this {
    this._cpus = count;
    return this;
  }

  memory(size: Mebibytes | number): this {
    this._memoryMib = Math.max(1, Math.floor(size));
    return this;
  }

  logLevel(level: LogLevel): this {
    this._logLevel = level;
    return this;
  }

  quietLogs(): this {
    this._quietLogs = true;
    return this;
  }

  workdir(path: string): this {
    this._workdir = path;
    return this;
  }

  shell(shell: string): this {
    this._shell = shell;
    return this;
  }

  // -- image-defined overrides -------------------------------------------

  entrypoint(cmd: Iterable<string>): this {
    this._entrypoint = Array.from(cmd);
    return this;
  }

  hostname(name: string): this {
    this._hostname = name;
    return this;
  }

  user(user: string): this {
    this._user = user;
    return this;
  }

  pullPolicy(policy: PullPolicy): this {
    this._pullPolicy = policy;
    return this;
  }

  /** Override the libkrunfw shared library path for this sandbox. */
  libkrunfwPath(path: string): this {
    this._libkrunfwPath = path;
    return this;
  }

  // -- env / scripts / lifecycle -----------------------------------------

  env(key: string, value: string): this {
    this._env.push([key, value]);
    return this;
  }

  envs(
    vars: Iterable<readonly [string, string]> | Record<string, string>,
  ): this {
    if (Symbol.iterator in vars) {
      for (const [k, v] of vars as Iterable<readonly [string, string]>) {
        this._env.push([k, v]);
      }
    } else {
      for (const [k, v] of Object.entries(vars)) this._env.push([k, v]);
    }
    return this;
  }

  script(name: string, content: string): this {
    this._scripts.push([name, content]);
    return this;
  }

  scripts(
    scripts: Iterable<readonly [string, string]> | Record<string, string>,
  ): this {
    if (Symbol.iterator in scripts) {
      for (const [k, v] of scripts as Iterable<readonly [string, string]>) {
        this._scripts.push([k, v]);
      }
    } else {
      for (const [k, v] of Object.entries(scripts)) this._scripts.push([k, v]);
    }
    return this;
  }

  replace(): this {
    this._replace = true;
    return this;
  }

  maxDuration(secs: number): this {
    this._maxDuration = secs;
    return this;
  }

  idleTimeout(secs: number): this {
    this._idleTimeout = secs;
    return this;
  }

  // -- mounts / patches --------------------------------------------------

  volume(
    guestPath: string,
    configure: (m: MountBuilder) => MountBuilder,
  ): this {
    try {
      const mount = configure(new MountBuilder(guestPath)).build();
      this._mounts.push(mount);
    } catch (e) {
      this._deferredError ??= e instanceof Error ? e : new Error(String(e));
    }
    return this;
  }

  patch(configure: (p: PatchBuilder) => PatchBuilder): this {
    const patches = configure(new PatchBuilder()).build();
    for (const p of patches) this._patches.push(p);
    return this;
  }

  addPatch(p: Patch): this {
    this._patches.push(p);
    return this;
  }

  // -- registry / networking ---------------------------------------------

  registry(
    configure: (r: RegistryConfigBuilder) => RegistryConfigBuilder,
  ): this {
    this._registry = configure(new RegistryConfigBuilder()).build();
    return this;
  }

  /** Publish a TCP port from host → guest. */
  port(hostPort: number, guestPort: number): this {
    this._portsTcp.push([hostPort, guestPort]);
    return this;
  }

  /** Publish a UDP port from host → guest. */
  portUdp(hostPort: number, guestPort: number): this {
    this._portsUdp.push([hostPort, guestPort]);
    return this;
  }

  /** Disable networking entirely. */
  disableNetwork(): this {
    this._disableNetwork = true;
    return this;
  }

  /** Configure networking with a `NetworkBuilder` callback. */
  network(configure: (n: NetworkBuilder) => NetworkBuilder): this {
    this._network = configure(new NetworkBuilder()).build();
    return this;
  }

  /**
   * Shorthand to add a secret. Auto-generates the placeholder as
   * `$MSB_<ENV_VAR>` and allows substitution only on `allowedHost`.
   */
  secretEnv(envVar: string, value: string, allowedHost: string): this {
    this._topLevelSecrets.push({
      envVar,
      value,
      placeholder: `$MSB_${envVar}`,
      allowedHosts: [allowedHost],
      allowedHostPatterns: [],
      allowAnyHost: false,
      requireTlsIdentity: true,
      injection: {},
    });
    return this;
  }

  /** Add a secret via a `SecretBuilder` callback. */
  secret(configure: (b: SecretBuilder) => SecretBuilder): this {
    this._topLevelSecrets.push(configure(new SecretBuilder()).build());
    return this;
  }

  // -- terminal ----------------------------------------------------------

  /** Materialize the accumulated state without creating a sandbox. */
  build(): SandboxConfig {
    if (this._deferredError) throw this._deferredError;
    if (this._image === null) {
      throw new InvalidConfigError("SandboxBuilder: .image(...) is required");
    }
    return {
      name: this._name,
      image: this._image,
      cpus: this._cpus,
      memoryMib: this._memoryMib,
      logLevel: this._logLevel,
      quietLogs: this._quietLogs,
      workdir: this._workdir,
      shell: this._shell,
      entrypoint: this._entrypoint?.slice() ?? null,
      cmd: this._cmd?.slice() ?? null,
      hostname: this._hostname,
      user: this._user,
      libkrunfwPath: this._libkrunfwPath,
      env: this._env.slice(),
      scripts: this._scripts.slice(),
      mounts: this._mounts.slice(),
      patches: this._patches.slice(),
      pullPolicy: this._pullPolicy,
      replace: this._replace,
      maxDurationSecs: this._maxDuration,
      idleTimeoutSecs: this._idleTimeout,
      portsTcp: this._portsTcp.slice(),
      portsUdp: this._portsUdp.slice(),
      registry: this._registry,
      network: this._network,
      disableNetwork: this._disableNetwork,
      secrets: this._topLevelSecrets.slice(),
    };
  }

  /** Create and start the sandbox in attached mode. */
  async create(): Promise<Sandbox> {
    const cfg = this.build();
    const napiCfg = sandboxConfigToNapi(cfg);
    const inner = await withMappedErrors(() => napi.Sandbox.create(napiCfg));
    return new Sandbox(inner, cfg.name, cfg);
  }

  /** Create and start the sandbox in detached mode (survives this process). */
  async createDetached(): Promise<Sandbox> {
    const cfg = this.build();
    const napiCfg = sandboxConfigToNapi(cfg);
    const inner = await withMappedErrors(() =>
      napi.Sandbox.createDetached(napiCfg),
    );
    return new Sandbox(inner, cfg.name, cfg, /*ownsLifecycle*/ false);
  }
}

/** Internal: marshal `SandboxConfig` into the binding's flat shape. */
export function sandboxConfigToNapi(cfg: SandboxConfig): NapiSandboxConfig {
  let imageStr: string;
  switch (cfg.image.kind) {
    case "oci":
      imageStr = cfg.image.reference;
      break;
    case "bind":
      imageStr = cfg.image.path;
      break;
    case "disk":
      imageStr = cfg.image.path;
      break;
  }

  const env = cfg.env.length > 0 ? Object.fromEntries(cfg.env) : undefined;
  const scripts =
    cfg.scripts.length > 0 ? Object.fromEntries(cfg.scripts) : undefined;
  const volumes =
    cfg.mounts.length > 0
      ? Object.fromEntries(cfg.mounts.map((m) => [m.guest, mountToNapi(m)]))
      : undefined;
  const patches =
    cfg.patches.length > 0 ? cfg.patches.map(patchToNapi) : undefined;
  const ports =
    cfg.portsTcp.length > 0
      ? Object.fromEntries(cfg.portsTcp.map(([h, g]) => [String(h), g]))
      : undefined;

  const registry = cfg.registry
    ? {
        auth: cfg.registry.auth ? registryAuthToNapi(cfg.registry.auth) : undefined,
        insecure: cfg.registry.insecure || undefined,
        caCertsPath: cfg.registry.caCertsPath ?? undefined,
      }
    : undefined;

  let network = cfg.network ? networkConfigToNapi(cfg.network) : undefined;
  // Carry the top-level publishedPort/secrets/etc. into the binding's flat
  // shape: ports map and secrets array live on the SandboxConfig itself.
  // The `network` field on the binding represents only DNS/TLS/policy/etc.
  if (cfg.disableNetwork) {
    // Today's binding lacks an explicit "off" flag — the policy preset
    // "none" produces the same effect.
    network = { ...(network ?? {}), policy: "none" };
  }
  // Network-builder ports merge with top-level builder ports.
  const networkPortsTcp =
    cfg.network?.ports.filter((p) => p.protocol === "tcp") ?? [];
  const networkPortsUdp =
    cfg.network?.ports.filter((p) => p.protocol === "udp") ?? [];

  const allPortsEntries: Array<readonly [string, number]> = [
    ...cfg.portsTcp.map(([h, g]) => [String(h), g] as const),
    ...networkPortsTcp.map((p) => [String(p.hostPort), p.guestPort] as const),
  ];
  const portsAll: Record<string, number> | undefined =
    allPortsEntries.length > 0 ? Object.fromEntries(allPortsEntries) : undefined;

  // UDP ports are not yet expressed in the binding's flat `ports` map
  // (which is TCP-only) — they'll be wired through once the binding gains
  // a separate UDP map. For now they are dropped; the typed surface
  // accepts them so user code remains correct.
  void networkPortsUdp;
  void cfg.portsUdp;

  const allSecrets = [
    ...cfg.secrets,
    ...(cfg.network?.secrets ?? []),
  ];
  const secrets =
    allSecrets.length > 0 ? allSecrets.map(secretEntryToNapi) : undefined;

  return {
    name: cfg.name,
    image: imageStr,
    memoryMib: cfg.memoryMib ?? undefined,
    cpus: cfg.cpus ?? undefined,
    workdir: cfg.workdir ?? undefined,
    shell: cfg.shell ?? undefined,
    entrypoint: cfg.entrypoint?.slice() ?? undefined,
    cmd: cfg.cmd?.slice() ?? undefined,
    hostname: cfg.hostname ?? undefined,
    libkrunfwPath: cfg.libkrunfwPath ?? undefined,
    user: cfg.user ?? undefined,
    env,
    scripts,
    volumes,
    patches,
    pullPolicy: cfg.pullPolicy ?? undefined,
    logLevel: cfg.logLevel ?? undefined,
    replace: cfg.replace || undefined,
    quietLogs: cfg.quietLogs || undefined,
    maxDurationSecs: cfg.maxDurationSecs ?? undefined,
    registry,
    ports: portsAll,
    network,
    secrets,
  };
}
