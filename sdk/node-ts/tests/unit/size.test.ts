import { describe, expect, it } from "vitest";
import { GiB, KiB, MiB, TiB } from "../../dist/index.js";

describe("size helpers", () => {
  it("MiB is the identity", () => {
    expect(MiB(100)).toBe(100);
  });

  it("GiB multiplies by 1024", () => {
    expect(GiB(2)).toBe(2048);
  });

  it("KiB divides by 1024", () => {
    expect(KiB(2048)).toBe(2);
  });

  it("TiB multiplies by 1024^2", () => {
    expect(TiB(1)).toBe(1024 * 1024);
  });
});
