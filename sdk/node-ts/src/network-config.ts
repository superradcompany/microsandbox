import type { NetworkPolicy } from "./policy/types.js";
import type { ViolationAction } from "./violation-action.js";

/** Inclusive port range in TCP/UDP terms. */
export interface PublishedPort {
  readonly hostPort: number;
  readonly guestPort: number;
  readonly protocol: "tcp" | "udp";
}

/** DNS interception configuration. */
export interface DnsConfig {
  readonly nameservers: readonly string[];
  readonly rebindProtection: boolean | null;
  readonly queryTimeoutMs: number | null;
}

/** TLS interception configuration. */
export interface TlsConfig {
  readonly bypass: readonly string[];
  readonly verifyUpstream: boolean | null;
  readonly interceptedPorts: readonly number[];
  readonly blockQuic: boolean | null;
  readonly upstreamCaCertPaths: readonly string[];
  readonly interceptCaCertPath: string | null;
  readonly interceptCaKeyPath: string | null;
}

/** Where in the HTTP request the secret value can be substituted. */
export interface SecretInjection {
  readonly headers?: boolean;
  readonly basicAuth?: boolean;
  readonly queryParams?: boolean;
  readonly body?: boolean;
}

/** A single secret entry — built via `SecretBuilder`. */
export interface SecretEntry {
  readonly envVar: string;
  readonly value: string;
  readonly placeholder: string | null;
  readonly allowedHosts: readonly string[];
  readonly allowedHostPatterns: readonly string[];
  readonly allowAnyHost: boolean;
  readonly requireTlsIdentity: boolean;
  readonly injection: SecretInjection;
}

/** Built network configuration produced by `NetworkBuilder.build()`. */
export interface NetworkConfig {
  readonly enabled: boolean;
  readonly ports: readonly PublishedPort[];
  readonly policy: NetworkPolicy | null;
  readonly dns: DnsConfig | null;
  readonly tls: TlsConfig | null;
  readonly secrets: readonly SecretEntry[];
  readonly secretViolation: ViolationAction | null;
  readonly maxConnections: number | null;
  readonly trustHostCAs: boolean;
}
