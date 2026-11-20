import { describe, expect, it, vi } from "vitest";
import { Snapshot } from "../../dist/snapshot-group.js";
import { UnsupportedError } from "../../dist/errors.js";
vi.mock("../../dist/internal/napi.js", () => ({ napi: {} }));
vi.mock("../../dist/sandbox.js", () => ({ Sandbox: class {} }));

const empty = { name: "history", path: "/store/history", head: null, checkpoint_count: 2, source: null };
function group(value: unknown) {
  return new Snapshot({ inspectJson: vi.fn().mockResolvedValue(JSON.stringify(value)) } as never);
}

describe("group inspection", () => {
  it("preserves a headless but populated unbound history", async () => {
    expect(await group(empty).inspect()).toEqual({ name: "history", path: "/store/history", head: null, checkpointCount: 2, source: null });
  });
  it.each(["available", "missing_sandbox", "different_catalog"])("preserves %s source identity without looking up its old name", async status => {
    const info = await group({ ...empty, source: { database_uuid: "catalog", sandbox_id: 19, recorded_name: "old", current_name: status === "available" ? "renamed" : null, status } }).inspect();
    expect(info.source).toEqual({ databaseUuid: "catalog", sandboxId: 19, recordedName: "old", currentName: status === "available" ? "renamed" : null, status });
  });
  it("refuses unsupported native libraries rather than guessing from head", async () => {
    await expect(new Snapshot({} as never).inspect()).rejects.toBeInstanceOf(UnsupportedError);
  });
  it.each([
    { ...empty, source: undefined }, { ...empty, checkpoint_count: -1 },
    { ...empty, source: { database_uuid: "catalog", sandbox_id: 1, recorded_name: "app", current_name: null, status: "available" } },
    { ...empty, source: { database_uuid: "catalog", sandbox_id: 1, recorded_name: "app", current_name: null, status: "future" } },
  ])("rejects malformed metadata instead of inventing an unbound association", async value => {
    await expect(group(value).inspect()).rejects.toThrow("Invalid native snapshot group inspection");
  });
});
