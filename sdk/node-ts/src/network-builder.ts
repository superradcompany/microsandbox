import { DnsBuilder } from "./dns-builder.js";
import { SecretBuilder } from "./secret-builder.js";
import { TlsBuilder } from "./tls-builder.js";
import type {
  DnsConfig,
  NetworkConfig,
  PublishedPort,
  SecretEntry,
  TlsConfig,
} from "./network-config.js";
import type { NetworkPolicy } from "./policy/types.js";
import type { ViolationAction } from "./violation-action.js";

export class NetworkBuilder {
  private _enabled = true;
  private _ports: PublishedPort[] = [];
  private _policy: NetworkPolicy | null = null;
  private _dns: DnsConfig | null = null;
  private _tls: TlsConfig | null = null;
  private _secrets: SecretEntry[] = [];
  private _secretViolation: ViolationAction | null = null;
  private _maxConnections: number | null = null;
  private _trustHostCAs = false;

  enabled(enabled: boolean): this {
    this._enabled = enabled;
    return this;
  }

  /** Publish a TCP port from host → guest. */
  port(hostPort: number, guestPort: number): this {
    this._ports.push({ hostPort, guestPort, protocol: "tcp" });
    return this;
  }

  /** Publish a UDP port from host → guest. */
  portUdp(hostPort: number, guestPort: number): this {
    this._ports.push({ hostPort, guestPort, protocol: "udp" });
    return this;
  }

  policy(policy: NetworkPolicy): this {
    this._policy = policy;
    return this;
  }

  dns(configure: (b: DnsBuilder) => DnsBuilder): this {
    this._dns = configure(new DnsBuilder()).build();
    return this;
  }

  tls(configure: (b: TlsBuilder) => TlsBuilder): this {
    this._tls = configure(new TlsBuilder()).build();
    return this;
  }

  secret(configure: (b: SecretBuilder) => SecretBuilder): this {
    this._secrets.push(configure(new SecretBuilder()).build());
    return this;
  }

  /**
   * Shorthand for adding a secret with an explicit placeholder and a
   * single allowed host. Sister to `SandboxBuilder.secretEnv` (3-arg)
   * which auto-generates the placeholder.
   */
  secretEnv(
    envVar: string,
    value: string,
    placeholder: string,
    allowedHost: string,
  ): this {
    this._secrets.push({
      envVar,
      value,
      placeholder,
      allowedHosts: [allowedHost],
      allowedHostPatterns: [],
      allowAnyHost: false,
      requireTlsIdentity: true,
      injection: {},
    });
    return this;
  }

  onSecretViolation(action: ViolationAction): this {
    this._secretViolation = action;
    return this;
  }

  maxConnections(max: number): this {
    this._maxConnections = max;
    return this;
  }

  /** Ship the host's trusted CAs into the guest at boot (off by default). */
  trustHostCAs(enabled: boolean): this {
    this._trustHostCAs = enabled;
    return this;
  }

  /** @internal */
  build(): NetworkConfig {
    return {
      enabled: this._enabled,
      ports: this._ports.slice(),
      policy: this._policy,
      dns: this._dns,
      tls: this._tls,
      secrets: this._secrets.slice(),
      secretViolation: this._secretViolation,
      maxConnections: this._maxConnections,
      trustHostCAs: this._trustHostCAs,
    };
  }
}
