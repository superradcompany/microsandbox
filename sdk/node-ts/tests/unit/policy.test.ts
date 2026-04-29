import { describe, expect, it } from "vitest";
import {
  Destination,
  NetworkPolicy,
  NetworkPolicyBuilder,
  PortRange,
  Rule,
} from "../../dist/index.js";

describe("NetworkPolicy presets", () => {
  it("none denies in both directions", () => {
    expect(NetworkPolicy.none()).toEqual({
      defaultEgress: "deny",
      defaultIngress: "deny",
      rules: [],
    });
  });

  it("allowAll allows in both directions", () => {
    expect(NetworkPolicy.allowAll()).toEqual({
      defaultEgress: "allow",
      defaultIngress: "allow",
      rules: [],
    });
  });

  it("publicOnly denies egress by default and adds an allow-public rule", () => {
    const p = NetworkPolicy.publicOnly();
    expect(p.defaultEgress).toBe("deny");
    expect(p.defaultIngress).toBe("allow");
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0]).toMatchObject({
      direction: "egress",
      action: "allow",
      destination: { kind: "group", group: "public" },
    });
  });

  it("nonLocal allows public + private egress", () => {
    const p = NetworkPolicy.nonLocal();
    expect(p.rules).toHaveLength(2);
    expect(p.rules[1]).toMatchObject({
      direction: "egress",
      destination: { kind: "group", group: "private" },
    });
  });
});

describe("Rule factory", () => {
  it("builds direction-specific allow/deny rules with empty proto/port sets", () => {
    const rule = Rule.allowEgress(Destination.cidr("10.0.0.0/8"));
    expect(rule).toMatchObject({
      direction: "egress",
      action: "allow",
      destination: { kind: "cidr", cidr: "10.0.0.0/8" },
      protocols: [],
      ports: [],
    });
  });

  it("anyDirection rules flag both ways", () => {
    expect(Rule.allowAny(Destination.any()).direction).toBe("any");
    expect(Rule.denyIngress(Destination.domain("x.com")).action).toBe("deny");
  });
});

describe("Destination factory", () => {
  it("constructs each variant", () => {
    expect(Destination.any()).toEqual({ kind: "any" });
    expect(Destination.cidr("1.2.3.4/32")).toEqual({
      kind: "cidr",
      cidr: "1.2.3.4/32",
    });
    expect(Destination.domain("example.com")).toEqual({
      kind: "domain",
      domain: "example.com",
    });
    expect(Destination.domainSuffix("example.com")).toEqual({
      kind: "domainSuffix",
      suffix: "example.com",
    });
    expect(Destination.group("metadata")).toEqual({
      kind: "group",
      group: "metadata",
    });
  });
});

describe("PortRange factory", () => {
  it("single collapses start === end", () => {
    expect(PortRange.single(443)).toEqual({ start: 443, end: 443 });
  });

  it("range carries both endpoints", () => {
    expect(PortRange.range(8000, 9000)).toEqual({ start: 8000, end: 9000 });
  });
});

describe("NetworkPolicyBuilder", () => {
  it("empty builder produces the asymmetric default", () => {
    const p = NetworkPolicy.builder().build();
    expect(p.defaultEgress).toBe("deny");
    expect(p.defaultIngress).toBe("allow");
    expect(p.rules).toHaveLength(0);
  });

  it("defaultDeny + per-direction override", () => {
    const p = NetworkPolicy.builder()
      .defaultDeny()
      .defaultIngress("allow")
      .build();
    expect(p.defaultEgress).toBe("deny");
    expect(p.defaultIngress).toBe("allow");
  });

  it("egress closure commits one rule per group shortcut, sharing state", () => {
    const p = NetworkPolicy.builder()
      .egress((e) => e.tcp().port(443).allowPublic().allowPrivate())
      .build();
    expect(p.rules).toHaveLength(2);
    expect(p.rules[0]).toMatchObject({
      direction: "egress",
      action: "allow",
      destination: { kind: "group", group: "public" },
      protocols: ["tcp"],
    });
    expect(p.rules[0].ports[0]).toEqual({ start: 443, end: 443 });
    expect(p.rules[1].destination.group).toBe("private");
  });

  it("explicit-ip rule via allow(d => d.ip(...))", () => {
    const p = NetworkPolicy.builder()
      .any((a) => a.deny((d) => d.ip("198.51.100.5")))
      .build();
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0]).toMatchObject({
      direction: "any",
      action: "deny",
      destination: { kind: "cidr", cidr: "198.51.100.5/32" },
    });
  });

  it("invalid IP surfaces at .build()", () => {
    const npb = NetworkPolicy.builder().egress((e) =>
      e.allow((d) => d.ip("not-an-ip")),
    );
    expect(() => npb.build()).toThrow(/invalid IP/i);
  });

  it("invalid port range surfaces at .build()", () => {
    const npb = NetworkPolicy.builder().egress((e) =>
      e.tcp().portRange(443, 80).allowPublic(),
    );
    expect(() => npb.build()).toThrow(/invalid port range/i);
  });

  it("missing direction surfaces at .build()", () => {
    const npb = NetworkPolicy.builder().rule((r) =>
      r.tcp().port(443).allowPublic(),
    );
    expect(() => npb.build()).toThrow(/direction not set/i);
  });

  it("ICMP in ingress rejected at .build()", () => {
    const npb = NetworkPolicy.builder().ingress((i) => i.icmpv4().allowPublic());
    expect(() => npb.build()).toThrow(/ICMP/);
  });

  it("allowLocal commits Loopback + LinkLocal + Host", () => {
    const p = NetworkPolicy.builder().egress((e) => e.allowLocal()).build();
    expect(p.rules.map((r) => r.destination.group)).toEqual([
      "loopback",
      "link-local",
      "host",
    ]);
  });

  it("can be used directly as input to NetworkBuilder.policy()", async () => {
    const { NetworkBuilder } = await import("../../dist/index.js");
    const nb = new NetworkBuilder();
    const npb = NetworkPolicy.builder()
      .defaultDeny()
      .egress((e) => e.tcp().port(443).allowPublic());
    // Should not throw — accepts both factory-produced objects and builder
    // instances.
    nb.policy(npb);
  });

  it("instanceof NetworkPolicyBuilder", () => {
    const npb = NetworkPolicy.builder();
    expect(npb).toBeInstanceOf(NetworkPolicyBuilder);
  });
});
