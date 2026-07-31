import { describe, expect, it } from "vitest";
import { SandboxListBuilder } from "../../dist/index.js";

describe("SandboxListBuilder", () => {
  it("combines pagination and AND-matched label options", () => {
    const options = new SandboxListBuilder()
      .limit(50)
      .cursor("next-page")
      .label("team", "sdk")
      .labels({ tier: "worker" })
      .toNapi();

    expect(options).toEqual({
      cursor: "next-page",
      limit: 50,
      labels: { team: "sdk", tier: "worker" },
    });
  });
});
