/** Action taken on a matching rule (or the per-direction default). */
export type Action = "allow" | "deny";

/** Direction the rule applies to. */
export type Direction = "egress" | "ingress" | "any";

/** Transport protocol filter. Empty `Rule.protocols` means "any protocol". */
export type Protocol = "tcp" | "udp" | "icmpv4" | "icmpv6";

export type DestinationGroup =
  | "public"
  | "loopback"
  | "private"
  | "link-local"
  | "metadata"
  | "multicast"
  | "host";

export const DestinationGroups: readonly DestinationGroup[] = [
  "public",
  "loopback",
  "private",
  "link-local",
  "metadata",
  "multicast",
  "host",
] as const;

/** Destination filter — see `Destination` factory for constructors. */
export type Destination =
  | { kind: "any" }
  | { kind: "cidr"; cidr: string }
  | { kind: "domain"; domain: string }
  | { kind: "domainSuffix"; suffix: string }
  | { kind: "group"; group: DestinationGroup };

/** Inclusive port range — see `PortRange.single` / `.range`. */
export interface PortRange {
  readonly start: number;
  readonly end: number;
}

/** A single ordered policy rule. */
export interface Rule {
  readonly direction: Direction;
  readonly destination: Destination;
  /** Empty = any protocol. */
  readonly protocols: readonly Protocol[];
  /** Empty = any port. Always interpreted as the guest-side port. */
  readonly ports: readonly PortRange[];
  readonly action: Action;
}

/**
 * Ordered rule list with per-direction defaults. First-match-wins is
 * evaluated independently for egress and ingress.
 */
export interface NetworkPolicy {
  readonly defaultEgress: Action;
  readonly defaultIngress: Action;
  readonly rules: readonly Rule[];
}
