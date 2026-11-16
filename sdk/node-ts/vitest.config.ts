import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Release scripts use node:test and are validated separately by release CI.
    include: ["tests/**/*.test.ts"],
    testTimeout: 300_000,
    hookTimeout: 300_000,
    fileParallelism: true,
    bail: 1,
  },
});
