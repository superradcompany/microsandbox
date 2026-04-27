import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isInstalled, Sandbox } from "../dist/index.js";

const SANDBOX_NAME = "sdk-smoke-test";

describe.skipIf(!isInstalled())("end-to-end smoke", () => {
  let sb: Sandbox;

  beforeAll(async () => {
    sb = await Sandbox.builder(SANDBOX_NAME)
      .image("mirror.gcr.io/library/alpine")
      .cpus(1)
      .memory(512)
      .replace()
      .create();
  });

  afterAll(async () => {
    await sb?.stopAndWait().catch(() => undefined);
    await Sandbox.remove(SANDBOX_NAME).catch(() => undefined);
  });

  it("exposes name synchronously", () => {
    expect(sb.name).toBe(SANDBOX_NAME);
  });

  it("runs a command via exec()", async () => {
    const out = await sb.exec("echo", ["hello"]);
    expect(out.success).toBe(true);
    expect(out.stdout()).toBe("hello\n");
  });

  it("streams events via execStream()", async () => {
    const handle = await sb.execStream("sh", [
      "-c",
      "echo a; echo b 1>&2; exit 7",
    ]);
    let stdout = "";
    let stderr = "";
    let code: number | null = null;
    for await (const ev of handle) {
      if (ev.kind === "stdout") stdout += new TextDecoder().decode(ev.data);
      if (ev.kind === "stderr") stderr += new TextDecoder().decode(ev.data);
      if (ev.kind === "exited") code = ev.code;
    }
    expect(stdout).toBe("a\n");
    expect(stderr).toBe("b\n");
    expect(code).toBe(7);
  });

  it("reads and writes files via SandboxFs", async () => {
    const fs = sb.fs();
    await fs.write("/tmp/x.txt", "data\n");
    expect(await fs.readToString("/tmp/x.txt")).toBe("data\n");
    expect(await fs.exists("/tmp/x.txt")).toBe(true);
    expect(await fs.exists("/tmp/missing.txt")).toBe(false);
  });

  it("snapshots metrics", async () => {
    const m = await sb.metrics();
    expect(m.timestamp).toBeInstanceOf(Date);
    expect(typeof m.cpuPercent).toBe("number");
  });
});
