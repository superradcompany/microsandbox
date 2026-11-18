import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("retains call-time paths, base meaning and backend for native imports", () => {
  // process.chdir is unsupported in workers and would affect unrelated tests.
  const script = fileURLToPath(new URL("../fixtures/snapshot-import-admission.mjs", import.meta.url));
  const root = realpathSync(mkdtempSync(join(tmpdir(), "msb-import-node-")));
  try {
    // Native process environment must be isolated before Bun or Node loads the binding.
    const env = { ...process.env, MSB_HOME: join(root, "home-a"), MSB_CONFIG_PATH: join(root, "absent.json") };
    const output = execFileSync(process.execPath, [script, root], { env, encoding: "utf8", timeout: 90_000 });
    expect(output).toContain("NODE_IMPORT_ADMISSION_OK");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 100_000);
