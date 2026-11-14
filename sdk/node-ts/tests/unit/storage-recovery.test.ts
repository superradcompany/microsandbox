import { beforeEach, describe, expect, it, vi } from "vitest";
const native = vi.hoisted(() => ({ Sandbox: { recoverStorage: vi.fn() } }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: native }));
import { recoverStorage } from "../../dist/storage-recovery.js";

beforeEach(() => { vi.resetAllMocks(); native.Sandbox.recoverStorage.mockResolvedValue(JSON.stringify({ name: "app", ready: true, originals_retained: true })); });

describe("storage recovery", () => {
  it("never invents acknowledgement and preserves complete-view selections", async () => {
    const result = await recoverStorage("app");
    expect(JSON.parse(native.Sandbox.recoverStorage.mock.calls[0]![1])).toEqual({ selections: [], accept_selected_view: false, legacy_writers_stopped: false });
    expect(result).toEqual({ name: "app", ready: true, originalsRetained: true });
    await recoverStorage("app", { selections: [{ diskId: "root", candidateId: "view" }], acceptSelectedView: true, legacyWritersStopped: true });
    expect(JSON.parse(native.Sandbox.recoverStorage.mock.calls[1]![1])).toEqual({ selections: [{ disk_id: "root", candidate_id: "view" }], accept_selected_view: true, legacy_writers_stopped: true });
  });
  it("requires a supporting native SDK rather than falling back to startup", async () => {
    const saved = native.Sandbox.recoverStorage;
    Object.assign(native.Sandbox, { recoverStorage: undefined });
    try { await expect(recoverStorage("app")).rejects.toThrow("upgrade or rebuild"); }
    finally { native.Sandbox.recoverStorage = saved; }
    expect(saved).not.toHaveBeenCalled();
  });
});
