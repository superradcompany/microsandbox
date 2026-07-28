import { describe, expect, it, vi } from "vitest";
import { ExecHandle } from "../../dist/index.js";

describe("ExecHandle", () => {
  it("forwards TTY resize dimensions to the native handle", async () => {
    const resize = vi.fn().mockResolvedValue(undefined);
    const handle = new ExecHandle({ resize } as never);

    await handle.resize(40, 120);

    expect(resize).toHaveBeenCalledOnce();
    expect(resize).toHaveBeenCalledWith(40, 120);
  });
});
