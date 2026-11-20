import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const FIXTURE = fileURLToPath(new URL("../types/service-update.ts", import.meta.url));

it("requires an options object with a target for Service updates", () => {
  expect(() => execFileSync(
    fileURLToPath(new URL("../../node_modules/typescript/bin/tsc", import.meta.url)),
    [
      "--noEmit",
      "--strict",
      "--target", "ES2023",
      "--module", "NodeNext",
      "--moduleResolution", "NodeNext",
      FIXTURE,
    ],
    { cwd: PACKAGE_ROOT, stdio: "pipe" },
  )).not.toThrow();
});
