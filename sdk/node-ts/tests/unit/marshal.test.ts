import { describe, expect, it } from "vitest";
import { GiB, MiB, NetworkBuilder, PortRange, Sandbox } from "../../dist/index.js";
import { sandboxConfigToNapi } from "../../dist/sandbox-builder.js";

describe("sandboxConfigToNapi", () => {
  it("renders an OCI rootfs as the bare reference string", () => {
    const cfg = Sandbox.builder("a").image("python:3.12").build();
    const napi = sandboxConfigToNapi(cfg);
    expect(napi.image).toBe("python:3.12");
    expect(napi.name).toBe("a");
  });

  it("flattens volumes keyed by guest path with the right shape", () => {
    const cfg = Sandbox.builder("a")
      .image("alpine")
      .volume("/data", (m) => m.named("vol-1").readonly())
      .volume("/scratch", (m) => m.tmpfs().size(MiB(50)))
      .volume("/seed", (m) => m.disk("./s.qcow2").fstype("ext4").readonly())
      .build();
    const napi = sandboxConfigToNapi(cfg);
    expect(napi.volumes).toEqual({
      "/data": { named: "vol-1", readonly: true },
      "/scratch": {
        tmpfs: true,
        sizeMib: 50,
        readonly: false,
      },
      "/seed": {
        disk: "./s.qcow2",
        format: "qcow2",
        fstype: "ext4",
        readonly: true,
      },
    });
  });

  it("emits the new policy schema with array protocols/ports", () => {
    const cfg = Sandbox.builder("a")
      .image("alpine")
      .network((n) =>
        n.policy({
          defaultEgress: "deny",
          defaultIngress: "allow",
          rules: [
            {
              direction: "egress",
              destination: { kind: "group", group: "public" },
              protocols: ["tcp", "udp"],
              ports: [PortRange.single(443), PortRange.range(8000, 9000)],
              action: "allow",
            },
          ],
        }),
      )
      .build();
    const napi = sandboxConfigToNapi(cfg);
    expect(napi.network?.rules).toEqual([
      {
        action: "allow",
        direction: "egress",
        destination: "public",
        protocols: ["tcp", "udp"],
        ports: ["443", "8000-9000"],
      },
    ]);
  });

  it("merges TCP ports from builder + network into a single map", () => {
    const cfg = Sandbox.builder("a")
      .image("alpine")
      .port(8080, 80)
      .network((n) => n.port(9000, 9000))
      .build();
    const napi = sandboxConfigToNapi(cfg);
    expect(napi.ports).toEqual({ "8080": 80, "9000": 9000 });
  });

  it("renders branded GiB/MiB sizes as bare numbers", () => {
    const cfg = Sandbox.builder("a").image("alpine").memory(GiB(1)).build();
    expect(sandboxConfigToNapi(cfg).memoryMib).toBe(1024);
  });

  it("auto-generates a placeholder for the 3-arg secretEnv shorthand", () => {
    const cfg = Sandbox.builder("a")
      .image("alpine")
      .secretEnv("API_KEY", "sk-1234", "api.example.com")
      .build();
    const napi = sandboxConfigToNapi(cfg);
    expect(napi.secrets).toEqual([
      {
        envVar: "API_KEY",
        value: "sk-1234",
        placeholder: "$MSB_API_KEY",
        allowHosts: ["api.example.com"],
        requireTls: true,
      },
    ]);
  });
});

describe("NetworkBuilder", () => {
  it("produces a NetworkConfig that tracks every setter", () => {
    const cfg = new NetworkBuilder()
      .port(8080, 80)
      .portUdp(5353, 53)
      .maxConnections(64)
      .trustHostCAs(true)
      .build();
    expect(cfg.ports).toEqual([
      { hostPort: 8080, guestPort: 80, protocol: "tcp" },
      { hostPort: 5353, guestPort: 53, protocol: "udp" },
    ]);
    expect(cfg.maxConnections).toBe(64);
    expect(cfg.trustHostCAs).toBe(true);
  });
});
