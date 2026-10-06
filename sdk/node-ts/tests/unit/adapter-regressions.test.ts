import { describe, expect, it } from "vitest";
import { AttachOptionsBuilder, ExecOptionsBuilder, NetworkBuilder, NetworkPolicy, Sandbox, SecretBuilder, TlsBuilder, RootDiskBuilder } from "../../dist/index.js";
import { remapKeysToCamel } from "../../dist/internal/config.js";

const invalidNumbers = [-1, 1.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1];

describe("adapter security regressions", () => {
  it("preserves accumulated network restrictions across callbacks", async () => {
    const config = await Sandbox.builder("adapter-network").image("alpine")
      .network(n => n.policy(NetworkPolicy.none()).maxTcpConnections(12)
        .secretEnvSimple("API_KEY", "real-secret", "api.example.com")
        .tls(t => t.bypass("internal.example")))
      .network(n => n.port(8080, 80)).build();
    expect(config.network).toMatchObject({
      policy: { defaultEgress: "deny", defaultIngress: "deny" }, maxTcpConnections: 12,
      secrets: { secrets: [{ envVar: "API_KEY", placeholder: "$MSB_API_KEY" }] },
      tls: { enabled: true, bypass: ["internal.example"] },
    });
  });

  it("preserves restrictions when a callback throws", async () => {
    const builder = Sandbox.builder("adapter-throw").image("alpine").network(n => n.policy(NetworkPolicy.none()));
    expect(() => builder.network(() => { throw new Error("callback failed"); })).toThrow();
    const config = await builder.build();
    expect(config.network.policy.defaultEgress).toBe("deny");
  });

  it.each(["simple", "explicit", "callback"])("enables TLS for %s secrets without erasing settings", mode => {
    const builder = new NetworkBuilder().tls(t => t.bypass("internal.example"));
    if (mode === "simple") builder.secretEnvSimple("API_KEY", "real-secret", "api.example.com");
    if (mode === "explicit") builder.secretEnv("API_KEY", "real-secret", "$TOKEN", "api.example.com");
    if (mode === "callback") builder.secret(s => s.env("API_KEY").value("real-secret").allow("api.example.com"));
    const config = builder.build();
    expect(config.tls).toMatchObject({ enabled: true, bypass: ["internal.example"] });
    expect(config.secrets.secrets[0].placeholder).not.toBe("real-secret");
  });

  it("returns a per-secret violation action", () => {
    expect(new SecretBuilder().env("TOKEN").value("secret").allow("example.com")
      .violationAction("block-and-terminate").build().violationAction).toBe("block-and-terminate");
  });

  it.each(invalidNumbers)("rejects invalid integer input %s before N-API can coerce it", value => {
    for (const builder of [new ExecOptionsBuilder(), new AttachOptionsBuilder(), Sandbox.builder("invalid")]) {
      expect(() => builder.rlimit("fsize", value)).toThrow();
      expect(() => builder.rlimitRange("fsize", 1, value)).toThrow();
    }
    expect(() => new NetworkBuilder().maxTcpConnections(value)).toThrow();
    expect(() => new NetworkBuilder().maxUdpConnections(value)).toThrow();
    expect(() => new NetworkBuilder().port(value, 80)).toThrow();
    expect(() => new TlsBuilder().interceptedPorts([value])).toThrow();
    expect(() => new RootDiskBuilder().size(value)).toThrow();
    expect(() => Sandbox.builder("invalid").cpus(value)).toThrow();
    expect(() => new ExecOptionsBuilder().timeout(value)).toThrow();
    const reusable = new NetworkBuilder().maxTcpConnections(12);
    expect(() => reusable.maxTcpConnections(value)).toThrow();
    expect(reusable.build().maxTcpConnections).toBe(12);
  });

  it("retains limits larger than 32 bits", async () => {
    for (const builder of [new ExecOptionsBuilder(), new AttachOptionsBuilder()]) {
      expect(builder.rlimit("fsize", 2 ** 32).build().rlimits[0]).toMatchObject({ soft: 2 ** 32, hard: 2 ** 32 });
    }
    const config = await Sandbox.builder("large-limit").image("alpine").rlimit("fsize", 2 ** 32).build();
    expect(JSON.stringify(config)).toContain("4294967296");
    expect(new NetworkBuilder().maxTcpConnections(2 ** 32).build().maxTcpConnections).toBe(2 ** 32);
    expect(() => new NetworkBuilder().port(2 ** 32, 80)).toThrow();
  });

  it("keeps user dictionary keys distinct in built config", async () => {
    const config = await Sandbox.builder("keys").image("alpine")
      .label("setup_db", "first").label("setupDb", "second")
      .script("setup_db", "echo first").script("setupDb", "echo second").build();
    expect(config.labels).toEqual({ setup_db: "first", setupDb: "second" });
    expect(config.runtime.scripts).toEqual({ setup_db: "echo first", setupDb: "echo second" });
  });

  it("preserves dictionary keys and converts schema fields for all config readers", () => {
    const config = remapKeysToCamel(JSON.parse('{"runtime":{"scripts":{"setup_db":"one","setupDb":"two","__proto__":"three"}},"labels":{"team_name":"four"},"resources":{"memory_mib":512}}'));
    expect(Object.keys(config.runtime.scripts)).toEqual(["setup_db", "setupDb", "__proto__"]);
    expect(config.labels.team_name).toBe("four");
    expect(config.resources.memoryMib).toBe(512);
  });
});
