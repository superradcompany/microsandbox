import { beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({ diagnoseStorage: vi.fn() }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: native }));
import { diagnoseStorage, type StorageSelection } from "../../dist/storage-diagnosis.js";
import { UnsupportedOperationError } from "../../dist/errors.js";

const wire = () => ({ home: "/selected/home", required_runtime_capability: "protected_guest_state", sandboxes: [
  { name: "app", status: "eligible", running: true, protection_registered: true, reason: null,
    inspection: { status: "eligible", reasons: [], estimated_bytes: "18446744073709551615", candidates: [
      { id: "view-1", disk_id: "root", layers: 2, virtual_size: "18446744073709551615", estimated_bytes: "0" },
    ] } },
  { name: "missing", status: "unavailable", running: false, protection_registered: false, reason: "not_found", inspection: null },
] });

beforeEach(() => { vi.resetAllMocks(); native.diagnoseStorage.mockResolvedValue(JSON.stringify(wire())); });

describe("diagnoseStorage", () => {
  it("preserves typed partial results and full-width byte counts", async () => {
    const report = await diagnoseStorage({ names: ["app", "missing"] }, { home: "/selected/home" });
    const [config, selection] = native.diagnoseStorage.mock.calls[0]!;
    expect(JSON.parse(config)).toEqual({ home: "/selected/home" });
    expect(JSON.parse(selection)).toEqual({ named: ["app", "missing"] });
    expect(report.sandboxes[0]?.running).toBe(true);
    expect(report.sandboxes[0]?.inspection?.previewAvailable).toBe(false);
    expect(report.sandboxes[0]?.guestMounts).toEqual({});
    expect(report.sandboxes[0]?.inspection?.candidates[0]?.virtualSize).toBe(2n ** 64n - 1n);
    expect(report.sandboxes[1]?.reason).toBe("not_found");
    await diagnoseStorage({ allSandboxes: true });
    expect(JSON.parse(native.diagnoseStorage.mock.calls[1]![1])).toBe("all");
  });

  it("requires explicit exclusive scope before native access", async () => {
    for (const selection of [{}, { names: [] }, { names: ["app"], allSandboxes: true }]) {
      await expect(diagnoseStorage(selection as StorageSelection)).rejects.toThrow("select sandbox names");
    }
    expect(native.diagnoseStorage).not.toHaveBeenCalled();
  });

  it("reports older native SDKs without falling back to another operation", async () => {
    const original = native.diagnoseStorage;
    Object.assign(native, { diagnoseStorage: undefined });
    try { await expect(diagnoseStorage({ names: ["app"] })).rejects.toBeInstanceOf(UnsupportedOperationError); }
    finally { native.diagnoseStorage = original; }
    expect(original).not.toHaveBeenCalled();
  });
});
