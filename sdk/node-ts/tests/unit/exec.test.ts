import { describe, expect, it, vi } from "vitest";
import { ExecHandle, Sandbox } from "../../dist/index.js";

describe("ExecHandle", () => {
  it("forwards TTY resize dimensions to the native handle", async () => {
    const resize = vi.fn().mockResolvedValue(undefined);
    const handle = new ExecHandle({ resize } as never);

    await handle.resize(40, 120);

    expect(resize).toHaveBeenCalledOnce();
    expect(resize).toHaveBeenCalledWith(40, 120);
  });
});

describe("Sandbox default workload", () => {
  it("delegates default execution without supplying a literal command", async () => {
    const execDefault = vi.fn().mockResolvedValue({
      code: 0,
      success: true,
      stdout: () => "ok",
      stderr: () => "",
      stdoutBytes: () => Buffer.from("ok"),
      stderrBytes: () => Buffer.alloc(0),
    });
    const sandbox = new Sandbox(
      { backendKind: "local", execDefault } as never,
      "worker",
    );

    const output = await sandbox.execDefault();

    expect(execDefault).toHaveBeenCalledOnce();
    expect(output.stdout()).toBe("ok");
  });
});
