import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it.skipIf(!process.env.MSB_TEST_CAPTURE_SANDBOX)("anchors native capture paths before scheduling", () => {
  // The child exclusively owns cwd changes and uses the real native extension.
  const script = fileURLToPath(new URL("../fixtures/snapshot-capture-admission.mjs", import.meta.url));
  const output = execFileSync(process.execPath, [script], { encoding: "utf8", timeout: 180_000 });
  expect(output).toContain("NODE_CAPTURE_ADMISSION_OK");
}, 190_000);
