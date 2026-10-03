import { beforeEach, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({ imagePrune: vi.fn() }));
vi.mock("../../dist/internal/napi.js", () => ({ napi: native }));
import { Image } from "../../dist/image.js";

beforeEach(() => vi.resetAllMocks());

it("preserves busy-entry counts and accepts reports from older native libraries", async () => {
  const report = {
    imageRefsRemoved: 1, manifestsRemoved: 1, layersRemoved: 0,
    fsmetaRemoved: 1, vmdkRemoved: 1, bytesReclaimed: undefined,
  };
  native.imagePrune.mockResolvedValue({ ...report, skippedInUse: 3 });
  expect(await Image.prune()).toMatchObject({ skippedInUse: 3, bytesReclaimed: null });
  native.imagePrune.mockResolvedValue(report);
  expect((await Image.prune()).skippedInUse).toBe(0);
});
