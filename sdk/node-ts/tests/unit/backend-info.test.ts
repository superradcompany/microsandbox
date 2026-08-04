import { describe, expect, it } from "vitest";

import { defaultBackendInfo, defaultBackendKind } from "../../dist/index.js";

describe("backend introspection", () => {
  it("returns structured, secret-safe default backend information", () => {
    const info = defaultBackendInfo();

    expect(["local", "cloud"]).toContain(info.kind);
    expect(info.kind).toBe(defaultBackendKind());
    expect(info).not.toHaveProperty("apiKey");
    expect(info).not.toHaveProperty("api_key");
    if (info.kind === "cloud") {
      expect(info.apiUrl).toMatch(/^https?:\/\//);
    } else {
      expect(info.apiUrl).toBeUndefined();
    }
  });
});
