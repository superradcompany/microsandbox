import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("../..", import.meta.url));

function loadPackageRoot(inputType: "commonjs" | "module", source: string): string {
  return execFileSync(process.execPath, [`--input-type=${inputType}`, "--eval", source], {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
  });
}

describe("package root exports", () => {
  it("loads through ESM import", () => {
    const output = loadPackageRoot(
      "module",
      'import { Sandbox } from "microsandbox"; process.stdout.write(typeof Sandbox);',
    );
    expect(output).toBe("function");
  });

  it("loads through CommonJS require", () => {
    const output = loadPackageRoot(
      "commonjs",
      'const { Sandbox } = require("microsandbox"); process.stdout.write(typeof Sandbox);',
    );
    expect(output).toBe("function");
  });
});
