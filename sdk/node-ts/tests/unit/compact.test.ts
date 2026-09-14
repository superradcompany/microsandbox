import { describe, expect, it, vi } from "vitest";

// CI runs these tests from build artifacts without the TypeScript source tree.
import { compactionResultFromJson, type DiskCompactionOptions } from "../../dist/compact.js";
import { Sandbox } from "../../dist/sandbox.js";
import { SandboxHandle } from "../../dist/sandbox-handle.js";
import type { NapiSandbox, NapiSandboxHandle } from "../../dist/internal/napi.js";

describe("disk compaction contract", () => {
  it("retains per-disk outcomes alongside aggregate metrics", () => {
    const result = compactionResultFromJson(JSON.stringify({
      dry_run: true, input_layers: 6, selected_layers: 4, output_layers: 4,
      materialized_bytes: 0, total_us: 10, pause_us: 0,
      disks: [{ guest_path: "/data", input_layers: 3, selected_layers: 2,
        output_layers: 2, materialized_bytes: 0, total_us: 4 }],
    }));
    expect(result.disks).toEqual([{ guestPath: "/data", inputLayers: 3,
      selectedLayers: 2, outputLayers: 2, materializedBytes: 0, totalUs: 4 }]);
    const options: DiskCompactionOptions = { disk: "/data", rootDiskOnly: false, layers: 999 };
    expect(options.disk).toBe("/data");
  });

  it("represents an empty default selection", () => {
    expect(compactionResultFromJson('{"disks":[]}').disks).toEqual([]);
  });

  it("forwards both selectors for shared validation without dropping either", async () => {
    const compact = vi.fn(async () => '{"disks":[]}');
    const sandbox = new Sandbox({ compact } as unknown as NapiSandbox, "worker");
    await sandbox.compact({ layers: 99, disk: "/data", rootDiskOnly: true, dryRun: true });
    expect(compact).toHaveBeenCalledWith(99, true, "/data", true);

    const handle = new SandboxHandle({ compact } as unknown as NapiSandboxHandle);
    await handle.compact({ disk: "/" });
    expect(compact).toHaveBeenLastCalledWith(undefined, undefined, "/", undefined);
    await handle.compact();
    expect(compact).toHaveBeenLastCalledWith(undefined, undefined, undefined, undefined);
  });
});
