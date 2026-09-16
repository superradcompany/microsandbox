import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { buildUnpublishedSdk } from "./build-unpublished-node-sdk.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

for (const failure of [undefined, "ci", "run"]) {
  test(`unpublished build restores publish metadata after ${failure ?? "success"}`, () => {
    const directory = mkdtempSync(join(tmpdir(), "msb-npm-release-test-"));
    try {
      mkdirSync(join(directory, "scripts"));
      copyFileSync(join(root, "sdk/node-ts/scripts/prune-platform-optional-deps.mjs"),
        join(directory, "scripts/prune-platform-optional-deps.mjs"));
      // Deliberately absent from the lock: this models a future, unpublished
      // platform version rather than relying on today's registry contents.
      const platform = "@superradcompany/microsandbox-darwin-arm64";
      const optionalDependencies = { [platform]: "999.0.0", "unrelated-optional": "1.0.0" };
      const manifest = JSON.stringify({ name: "fixture", optionalDependencies });
      const lock = JSON.stringify({ lockfileVersion: 3, packages: {
        "": { optionalDependencies },
        "node_modules/unrelated-optional": { version: "1.0.0" },
      } });
      writeFileSync(join(directory, "package.json"), manifest);
      writeFileSync(join(directory, "package-lock.json"), lock);
      const calls = [];
      const run = (command, args) => {
        calls.push([command, ...args]);
        const pkg = JSON.parse(readFileSync(join(directory, "package.json")));
        const installedLock = JSON.parse(readFileSync(join(directory, "package-lock.json")));
        assert.deepEqual(pkg.optionalDependencies, { "unrelated-optional": "1.0.0" });
        assert.deepEqual(installedLock.packages[""].optionalDependencies, pkg.optionalDependencies);
        assert.equal(installedLock.packages["node_modules/unrelated-optional"].version, "1.0.0");
        if (args[0] === failure) throw new Error("injected failure");
      };
      if (failure) assert.throws(() => buildUnpublishedSdk(directory, run), /injected failure/);
      else buildUnpublishedSdk(directory, run);
      assert.equal(readFileSync(join(directory, "package.json"), "utf8"), manifest);
      assert.equal(readFileSync(join(directory, "package-lock.json"), "utf8"), lock);
      assert.deepEqual(calls, failure === "ci"
        ? [["npm", "ci", "--omit=optional"]]
        : [["npm", "ci", "--omit=optional"], ["npm", "run", "build:ts"]]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("all ten packages published with provenance identify this repository", () => {
  const directories = ["sdk/node-ts",
    ...["darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu", "win32-arm64-msvc", "win32-x64-msvc"].map((name) => `sdk/node-ts/npm/${name}`),
    ...["microsandbox-types", "protocol-client", "agent-client", "control-client"].map((name) => `packages/${name}/typescript`)];
  for (const directory of directories) {
    const pkg = JSON.parse(readFileSync(join(root, directory, "package.json")));
    assert.deepEqual(pkg.repository, {
      type: "git", url: "git+https://github.com/superradcompany/microsandbox.git", directory,
    });
  }
});

test("release builds before publishing and resolves platform dependencies after indexing", () => {
  const workflow = readFileSync(join(root, ".github/workflows/release.yml"), "utf8");
  const publisher = workflow.split("\n  npm-publish:\n")[1].split("\n  refresh-lockfile:\n")[0];
  assert.match(publisher, /id-token: write/);
  assert.match(publisher, /NPM_CONFIG_PROVENANCE: "true"/);
  assert.match(publisher, /runs-on: ubuntu-latest/);
  const names = ["Publish platform packages", "Wait for npm to index platform packages",
    "Build TypeScript output with published platform dependencies", "Verify root package platform dependencies", "Publish root package"];
  let previous = -1;
  for (const name of names) {
    const index = publisher.indexOf(`- name: ${name}`);
    assert.ok(index > previous, `missing or out of order: ${name}`);
    previous = index;
  }
  assert.match(publisher, /npm install --package-lock-only --ignore-scripts\s+npm ci --omit=optional\s+npm run build:ts/);
  assert.match(workflow, /node ..\/..\/scripts\/ci\/build-unpublished-node-sdk.mjs/);
});
