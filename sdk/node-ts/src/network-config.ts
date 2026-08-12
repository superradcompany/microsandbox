import type { NetworkPolicy } from "./policy/types.js";
import type { ViolationAction } from "./violation-action.js";

/** Inclusive port range in TCP/UDP terms. */
export interface PublishedPort {
  readonly hostPort: number;
  readonly guestPort: number;
  readonly protocol: "tcp" | "udp";
  readonly hostBind: string;
}

/** DNS interception configuration. */
export interface DnsConfig {
  readonly nameservers: readonly string[];
  readonly rebindProtection: boolean | null;
  readonly queryTimeoutMs: number | null;
}

/** Host-scoped upstream CA certificate path. */
export interface ScopedUpstreamCaCert {
  readonly pattern: string;
  readonly path: string;
}

/** Host-scoped upstream certificate verification override. */
export interface ScopedVerifyUpstream {
  readonly pattern: string;
  readonly verify: boolean;
}

/** TLS interception configuration. */
export interface TlsConfig {
  readonly bypass: readonly string[];
  readonly verifyUpstream: boolean | null;
  readonly interceptedPorts: readonly number[];
  readonly blockQuic: boolean | null;
  readonly upstreamCaCertPaths: readonly string[];
  readonly scopedUpstreamCaCerts: readonly ScopedUpstreamCaCert[];
  readonly scopedVerifyUpstream: readonly ScopedVerifyUpstream[];
  readonly interceptCaCertPath: string | null;
  readonly interceptCaKeyPath: string | null;
}

/** One token bucket of a rate limiter: starts full, refills continuously. */
export interface TokenBucketConfig {
  readonly size: number;
  readonly refillTimeMs: number;
  readonly oneTimeBurst: number;
}

/** Rate limiter for one direction. A missing bucket means unlimited. */
export interface RateLimiterConfig {
  readonly bandwidth?: TokenBucketConfig;
  readonly ops?: TokenBucketConfig;
}

/** Local network rate limits grouped by traffic direction. */
export interface NetworkRateLimiterConfig {
  readonly egress?: RateLimiterConfig;
  readonly ingress?: RateLimiterConfig;
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
  readonly rateLimiter: NetworkRateLimiterConfig | null;
  readonly interface?: {
    readonly ipv4Pool?: string | null;
    readonly ipv6Pool?: string | null;
    readonly ipv4Address?: string | null;
    readonly ipv6Address?: string | null;
    readonly mac?: readonly number[] | null;
    readonly mtu?: number | null;
  };
  readonly trustHostCAs: boolean;
}
