import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("retains call-time paths, base meaning and backend for native imports", () => {
  // process.chdir is unsupported in workers and would affect unrelated tests.
  const script = fileURLToPath(new URL("../fixtures/snapshot-import-admission.mjs", import.meta.url));
  const output = execFileSync(process.execPath, [script], { encoding: "utf8", timeout: 90_000 });
  expect(output).toContain("NODE_IMPORT_ADMISSION_OK");
}, 100_000);
