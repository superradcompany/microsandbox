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

export const Rule = {
  allowEgress: allowEgressRule,
  denyEgress: denyEgressRule,
  allowIngress: allowIngressRule,
  denyIngress: denyIngressRule,
  allowAny: allowAnyRule,
  denyAny: denyAnyRule,
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

  /** Egress allowed only to public destinations; ingress allowed by default. */
  publicOnly: (): Types.NetworkPolicy => ({
    defaultEgress: "deny",
    defaultIngress: "allow",
    rules: [allowEgressRule({ kind: "group", group: "public" })],
  }),

  /** Egress allowed to public + private (LAN); ingress allowed by default. */
  nonLocal: (): Types.NetworkPolicy => ({
    defaultEgress: "deny",
    defaultIngress: "allow",
    rules: [
      allowEgressRule({ kind: "group", group: "public" }),
      allowEgressRule({ kind: "group", group: "private" }),
    ],
  }),
};
