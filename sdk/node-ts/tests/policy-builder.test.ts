/// <reference types="node" />
import { describe, it, expect } from "vitest";
import { NetworkPolicy, PolicyAction } from "../index.mjs";

// Pure-shape tests — no sandbox runtime required. Verifies that the
// fluent NetworkPolicyBuilder produces the expected `NetworkConfig`
// shape and that chaining works end-to-end.

describe("NetworkPolicyBuilder", () => {
	it("empty builder produces an empty rules array and unset defaults", () => {
		const cfg = NetworkPolicy.builder().build();
		expect(cfg.rules).toEqual([]);
		expect(cfg.defaultEgress).toBeUndefined();
		expect(cfg.defaultIngress).toBeUndefined();
		expect(cfg.policy).toBeUndefined();
	});

	it("defaultDeny sets both directions to deny", () => {
		const cfg = NetworkPolicy.builder().defaultDeny().build();
		expect(cfg.defaultEgress).toBe("deny");
		expect(cfg.defaultIngress).toBe("deny");
	});

	it("defaultEgress / defaultIngress override individually", () => {
		const cfg = NetworkPolicy.builder()
			.defaultDeny()
			.defaultIngress(PolicyAction.Allow)
			.build();
		expect(cfg.defaultEgress).toBe("deny");
		expect(cfg.defaultIngress).toBe("allow");
	});

	it("egress sub-builder commits one rule per shortcut", () => {
		const cfg = NetworkPolicy.builder()
			.defaultDeny()
			.egress()
			.tcp()
			.port(443)
			.allowPublic()
			.allowPrivate()
			.build();
		expect(cfg.rules).toHaveLength(2);
		expect(cfg.rules![0]).toMatchObject({
			action: "allow",
			direction: "egress",
			destination: "public",
			protocol: "tcp",
			port: "443",
		});
		expect(cfg.rules![1]).toMatchObject({
			action: "allow",
			direction: "egress",
			destination: "private",
			protocol: "tcp",
			port: "443",
		});
	});

	it("allowLocal expands to three rules (loopback + link-local + host)", () => {
		const cfg = NetworkPolicy.builder().egress().allowLocal().build();
		expect(cfg.rules).toHaveLength(3);
		expect(cfg.rules!.map((r) => r.destination)).toEqual([
			"loopback",
			"link-local",
			"host",
		]);
	});

	it("allow_host vs allow_loopback target different groups", () => {
		const cfg = NetworkPolicy.builder()
			.egress()
			.allowHost()
			.allowLoopback()
			.build();
		expect(cfg.rules!.map((r) => r.destination)).toEqual(["host", "loopback"]);
	});

	it("explicit-destination shortcuts commit with the IP / CIDR / domain", () => {
		const cfg = NetworkPolicy.builder()
			.any()
			.denyIp("198.51.100.5")
			.egress()
			.tcp()
			.port(443)
			.allowDomain("api.example.com")
			.allowDomainSuffix(".pythonhosted.org")
			.allowCidr("10.0.0.0/8")
			.build();
		expect(cfg.rules).toHaveLength(4);
		expect(cfg.rules![0]).toMatchObject({
			action: "deny",
			direction: "any",
			destination: "198.51.100.5",
		});
		expect(cfg.rules![1]).toMatchObject({
			action: "allow",
			direction: "egress",
			destination: "api.example.com",
			protocol: "tcp",
			port: "443",
		});
		expect(cfg.rules![2].destination).toBe(".pythonhosted.org");
		expect(cfg.rules![3].destination).toBe("10.0.0.0/8");
	});

	it("portRange formats as <lo>-<hi> on the wire", () => {
		const cfg = NetworkPolicy.builder()
			.egress()
			.tcp()
			.portRange(80, 443)
			.allowPublic()
			.build();
		expect(cfg.rules![0].port).toBe("80-443");
	});

	it("protocol set dedupes on insert", () => {
		const cfg = NetworkPolicy.builder()
			.egress()
			.tcp()
			.tcp()
			.udp()
			.tcp()
			.allowPublic()
			.build();
		// First protocol wins on the wire (rules carry one protocol per entry today);
		// the dedup just prevents the set from growing past the unique values.
		expect(cfg.rules![0].protocol).toBe("tcp");
	});
});
