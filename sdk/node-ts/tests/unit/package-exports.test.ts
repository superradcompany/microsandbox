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
  for (const inputType of ["module", "commonjs"] as const) {
    it(`exports the native error subclasses through ${inputType}`, () => {
      const names = [
        "BootStartError",
        "AgentClientError",
        "WindowsHostSetupError",
        "ExecFailedError",
        "NetworkBuilderError",
        "SnapshotNotFoundError",
        "SnapshotAlreadyExistsError",
        "SnapshotSandboxRunningError",
        "SnapshotImageMissingError",
        "SnapshotIntegrityError",
        "SnapshotMigrationError",
        "MissedRotationError",
        "InvalidCursorError",
      ];
      const loader = inputType === "module"
        ? 'import * as sdk from "microsandbox";'
        : 'const sdk = require("microsandbox");';

      const output = loadPackageRoot(
        inputType,
        `${loader} const names = ${JSON.stringify(names)};
         process.stdout.write(JSON.stringify(names.map((name) => typeof sdk[name])));`,
      );

      expect(JSON.parse(output)).toEqual(names.map(() => "function"));
    });
  }

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
