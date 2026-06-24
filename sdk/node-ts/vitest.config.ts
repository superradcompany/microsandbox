import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 300_000,
    hookTimeout: 300_000,
    fileParallelism: true,
    bail: 1,
  },
});
