import { describe, expect, it } from "vitest";
import {
  Destination,
  NetworkPolicy,
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
