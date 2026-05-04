import { describe, expect, it } from "vitest";
import {
  GiB,
  InterfaceOverridesBuilder,
  intoRootfsSource,
  InvalidConfigError,
  MiB,
  MountBuilder,
  NetworkBuilder,
  PatchBuilder,
  Sandbox,
  Stdin,
} from "../../dist/index.js";

describe("intoRootfsSource", () => {
  it("treats absolute paths as bind mounts", () => {
    expect(intoRootfsSource("/srv/rootfs")).toEqual({
      kind: "bind",
      path: "/srv/rootfs",
    });
  });

  it("treats relative paths as bind mounts", () => {
    expect(intoRootfsSource("./rootfs")).toEqual({
      kind: "bind",
      path: "./rootfs",
    });
  });

  it("recognises disk-image extensions regardless of leading slash", () => {
    expect(intoRootfsSource("./alpine.qcow2")).toEqual({
      kind: "disk",
      path: "./alpine.qcow2",
      format: "qcow2",
    });
    expect(intoRootfsSource("foo.raw")).toEqual({
      kind: "disk",
      path: "foo.raw",
      format: "raw",
    });
  });

  it("falls back to OCI references", () => {
    expect(intoRootfsSource("python:3.12")).toEqual({
      kind: "oci",
      reference: "python:3.12",
    });
  });

  it("passes through structured RootfsSource values", () => {
    const src = { kind: "oci" as const, reference: "alpine" };
    expect(intoRootfsSource(src)).toBe(src);
  });
});

describe("MountBuilder", () => {
  it("builds a bind mount with default writeable flag", () => {
    const m = new MountBuilder("/data").bind("/host/data").build();
    expect(m).toEqual({
      kind: "bind",
      host: "/host/data",
      guest: "/data",
      readonly: false,
    });
  });

  it("builds a tmpfs mount with size and uniform readonly", () => {
    const m = new MountBuilder("/scratch").tmpfs().size(MiB(64)).readonly().build();
    expect(m).toEqual({
      kind: "tmpfs",
      guest: "/scratch",
      sizeMib: 64,
      readonly: true,
    });
  });

  it("auto-infers disk format from the host extension", () => {
    const m = new MountBuilder("/seed")
      .disk("./fixture.qcow2")
      .fstype("ext4")
      .readonly()
      .build();
    expect(m).toMatchObject({
      kind: "disk",
      host: "./fixture.qcow2",
      format: "qcow2",
      fstype: "ext4",
      readonly: true,
    });
  });

  it("rejects .size() on a non-tmpfs mount", () => {
    const builder = new MountBuilder("/data").bind("/host").size(MiB(10));
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("rejects .format() on a non-disk mount", () => {
    const builder = new MountBuilder("/data")
      .bind("/host")
      .format("qcow2");
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("rejects .fstype() on a non-disk mount", () => {
    const builder = new MountBuilder("/data")
      .bind("/host")
      .fstype("ext4");
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("rejects unset mount kind", () => {
    expect(() => new MountBuilder("/data").build()).toThrow(InvalidConfigError);
  });

  it("rejects fstypes containing forbidden separators", () => {
    const builder = new MountBuilder("/data").disk("./d.raw").fstype("ext4,foo");
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("rejects relative guest paths", () => {
    const builder = new MountBuilder("data").bind("/host");
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("rejects guest paths containing : or ;", () => {
    const builder = new MountBuilder("/foo:bar").bind("/host");
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });
});

describe("PatchBuilder", () => {
  it("collects patches in declaration order", () => {
    const patches = new PatchBuilder()
      .text("/etc/cfg", "x", { mode: 0o644 })
      .mkdir("/var/cache", { mode: 0o755 })
      .copyFile("./host.pem", "/etc/cert.pem", { replace: true })
      .build();
    expect(patches).toHaveLength(3);
    expect(patches[0]).toMatchObject({ kind: "text", mode: 0o644 });
    expect(patches[1]).toMatchObject({ kind: "mkdir", mode: 0o755 });
    expect(patches[2]).toMatchObject({ kind: "copyFile", replace: true });
  });
});

describe("SandboxBuilder.build", () => {
  it("requires .image()", () => {
    expect(() => Sandbox.builder("x").build()).toThrow(InvalidConfigError);
  });

  it("renders branded sizes back to plain numbers", () => {
    const cfg = Sandbox.builder("x").image("alpine").memory(GiB(2)).build();
    expect(cfg.memoryMib).toBe(2048);
  });

  it("collects volumes through the MountBuilder callback", () => {
    const cfg = Sandbox.builder("x")
      .image("alpine")
      .volume("/data", (m) => m.named("v1").readonly())
      .volume("/tmp", (m) => m.tmpfs().size(MiB(64)))
      .build();
    expect(cfg.mounts).toHaveLength(2);
    // The Rust VolumeMount enum serializes externally-tagged: each
    // entry is `{ type: "Named", name, guest, readonly }` etc.
    expect(cfg.mounts[0]).toMatchObject({
      type: "Named",
      name: "v1",
      readonly: true,
    });
    expect(cfg.mounts[1]).toMatchObject({
      type: "Tmpfs",
      sizeMib: 64,
    });
  });

  it("invalid volume invocations defer to .build() / .create()", () => {
    const builder = Sandbox.builder("x")
      .image("alpine")
      .volume("/bad", (m) => m.bind("/host").size(MiB(1)));
    expect(() => builder.build()).toThrow(InvalidConfigError);
  });

  it("defaults metricsSampleIntervalMs to 1000", () => {
    const cfg = Sandbox.builder("x").image("alpine").build();
    expect(cfg.metricsSampleIntervalMs).toBe(1000);
  });

  it("metricsSampleIntervalMs sets the persisted value", () => {
    const cfg = Sandbox.builder("x")
      .image("alpine")
      .metricsSampleIntervalMs(5000)
      .build();
    expect(cfg.metricsSampleIntervalMs).toBe(5000);
  });

  it("metricsSampleIntervalMs(0) disables sampling", () => {
    const cfg = Sandbox.builder("x")
      .image("alpine")
      .metricsSampleIntervalMs(0)
      .build();
    expect(cfg.metricsSampleIntervalMs).toBe(0);
  });

  it("disableMetricsSample overrides metricsSampleIntervalMs", () => {
    const cfg = Sandbox.builder("x")
      .image("alpine")
      .metricsSampleIntervalMs(5000)
      .disableMetricsSample()
      .build();
    expect(cfg.metricsSampleIntervalMs).toBe(5000);
    expect(cfg.disableMetricsSample).toBe(true);
  });
});

describe("InterfaceOverridesBuilder", () => {
  it("constructs cleanly and accepts MTU + IPv4 + IPv6 + MAC", () => {
    const b = new InterfaceOverridesBuilder()
      .mtu(9000)
      .ipv4("100.96.0.5")
      .ipv6("fd42:6d73:62::5")
      .mac("aa:bb:cc:dd:ee:ff");
    expect(b).toBeInstanceOf(InterfaceOverridesBuilder);
  });

  it("MTU out of range rejected at the call", () => {
    expect(() => new InterfaceOverridesBuilder().mtu(70_000)).toThrow();
  });

  it("invalid IPv4 surfaces at .interface() drain", () => {
    expect(() =>
      new NetworkBuilder().interface((io) => io.ipv4("999.999.999.999")),
    ).toThrow(/invalid IPv4/);
  });

  it("invalid MAC surfaces", () => {
    expect(() =>
      new NetworkBuilder().interface((io) => io.mac("zz:zz:zz:zz:zz:zz")),
    ).toThrow(/MAC/);
  });

  it("valid overrides flow through NetworkBuilder.build()", () => {
    const cfg = new NetworkBuilder()
      .interface((io) => io.mtu(9000).ipv4("100.96.0.5"))
      .build() as { interface: { mtu: number; ipv4Address: string } };
    expect(cfg.interface.mtu).toBe(9000);
    expect(cfg.interface.ipv4Address).toBe("100.96.0.5");
  });
});

describe("NetworkBuilder.secretEnvSimple (3-arg shorthand)", () => {
  it("accepts the 3-arg form mirroring Rust core", () => {
    const cfg = new NetworkBuilder()
      .secretEnvSimple("API_KEY", "sk-abc", "api.example.com")
      .build() as {
        secrets: { secrets: ReadonlyArray<{ envVar: string; placeholder: string }> };
      };
    expect(cfg.secrets.secrets).toHaveLength(1);
    expect(cfg.secrets.secrets[0].envVar).toBe("API_KEY");
    // Placeholder defaults to the value when omitted.
    expect(cfg.secrets.secrets[0].placeholder).toBe("sk-abc");
  });
});

describe("Stdin factory", () => {
  it("emits the right discriminants", () => {
    expect(Stdin.null()).toEqual({ kind: "null" });
    expect(Stdin.pipe()).toEqual({ kind: "pipe" });
    const bytes = Stdin.bytes("hello");
    expect(bytes).toMatchObject({ kind: "bytes" });
    if (bytes.kind === "bytes") {
      expect(new TextDecoder().decode(bytes.data)).toBe("hello");
    }
  });
});
