import type * as Types from "./types.js";

const empty = Object.freeze([]) as readonly never[];

const allowEgressRule = (destination: Types.Destination): Types.Rule => ({
  direction: "egress",
  destination,
  protocols: empty,
  ports: empty,
  action: "allow",
});

const denyEgressRule = (destination: Types.Destination): Types.Rule => ({
  direction: "egress",
  destination,
  protocols: empty,
  ports: empty,
  action: "deny",
});

const allowIngressRule = (destination: Types.Destination): Types.Rule => ({
  direction: "ingress",
  destination,
  protocols: empty,
  ports: empty,
  action: "allow",
});

const denyIngressRule = (destination: Types.Destination): Types.Rule => ({
  direction: "ingress",
  destination,
  protocols: empty,
  ports: empty,
  action: "deny",
});

const allowAnyRule = (destination: Types.Destination): Types.Rule => ({
  direction: "any",
  destination,
  protocols: empty,
  ports: empty,
  action: "allow",
});

const denyAnyRule = (destination: Types.Destination): Types.Rule => ({
  direction: "any",
  destination,
  protocols: empty,
  ports: empty,
  action: "deny",
});

/**
 * Allow plain DNS (UDP/53 and TCP/53) to the sandbox gateway, i.e. the
 * in-process DNS forwarder. The standard one-liner for opening DNS
 * under a deny-by-default policy. DoT (TCP/853) is intentionally not
 * included; add an explicit `Group::Host tcp/853` allow rule if needed.
 */
const allowDnsRule = (): Types.Rule => ({
  direction: "egress",
  destination: { kind: "group", group: "host" },
  protocols: ["udp", "tcp"],
  ports: [{ start: 53, end: 53 }],
  action: "allow",
});

const denyDnsRule = (): Types.Rule => ({
  ...allowDnsRule(),
  action: "deny",
});

export const Rule = {
  allowEgress: allowEgressRule,
  denyEgress: denyEgressRule,
  allowIngress: allowIngressRule,
  denyIngress: denyIngressRule,
  allowAny: allowAnyRule,
  denyAny: denyAnyRule,
  allowDns: allowDnsRule,
  denyDns: denyDnsRule,
};

export const Destination = {
  any: (): Types.Destination => ({ kind: "any" }),
  cidr: (cidr: string): Types.Destination => ({ kind: "cidr", cidr }),
  domain: (domain: string): Types.Destination => ({ kind: "domain", domain }),
  domainSuffix: (suffix: string): Types.Destination => ({
    kind: "domainSuffix",
    suffix,
  }),
  group: (group: Types.DestinationGroup): Types.Destination => ({
    kind: "group",
    group,
  }),
};

export const PortRange = {
  single: (port: number): Types.PortRange => ({ start: port, end: port }),
  range: (start: number, end: number): Types.PortRange => ({ start, end }),
};

export const NetworkPolicy = {
  /** Deny everything in both directions. */
  none: (): Types.NetworkPolicy => ({
    defaultEgress: "deny",
    defaultIngress: "deny",
    rules: [],
  }),

  /** Allow everything in both directions. */
  allowAll: (): Types.NetworkPolicy => ({
    defaultEgress: "allow",
    defaultIngress: "allow",
    rules: [],
  }),

  /** Build a canonical deny-by-default policy from composable profiles. */
  fromProfiles: (
    profiles: Iterable<Types.NetworkProfile>,
  ): Types.NetworkPolicy => {
    const requested = new Set(profiles);
    const canonical: readonly Types.NetworkProfile[] = [
      "public",
      "private",
      "host",
    ];
    for (const profile of requested) {
      if (!canonical.includes(profile)) {
        throw new RangeError(`unknown network profile: ${String(profile)}`);
      }
    }
    return {
      defaultEgress: "deny",
      defaultIngress: "allow",
      rules: [
        ...(requested.size > 0 ? [allowDnsRule()] : []),
        ...canonical
          .filter((profile) => requested.has(profile))
          .map((group) => allowEgressRule({ kind: "group", group })),
      ],
    };
  },
};
