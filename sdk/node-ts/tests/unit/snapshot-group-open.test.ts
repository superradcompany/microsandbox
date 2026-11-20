import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it.skipIf(!process.env.MSB_TEST_NATIVE_MODULE)("retains explicit native group paths across cwd changes", () => {
  const script = fileURLToPath(new URL("../fixtures/snapshot-group-open.mjs", import.meta.url));
  const output = execFileSync(process.execPath, [script], { encoding: "utf8", timeout: 90_000 });
  expect(output).toContain("NODE_GROUP_OPEN_OK");
}, 100_000);
