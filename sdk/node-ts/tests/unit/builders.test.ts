import { describe, expect, it } from "vitest";
import {
  GiB,
  intoRootfsSource,
  InvalidConfigError,
  MiB,
  MountBuilder,
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
    expect(cfg.mounts[0]).toMatchObject({
      kind: "named",
      name: "v1",
      readonly: true,
    });
    expect(cfg.mounts[1]).toMatchObject({
      kind: "tmpfs",
      sizeMib: 64,
    });
  });

  it("invalid volume invocations defer to .build() / .create()", () => {
    const builder = Sandbox.builder("x")
      .image("alpine")
      .volume("/bad", (m) => m.bind("/host").size(MiB(1)));
    expect(() => builder.build()).toThrow(InvalidConfigError);
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
