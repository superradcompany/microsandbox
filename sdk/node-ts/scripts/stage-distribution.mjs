import { cp, mkdir, readFile, writeFile, access } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

// Staging is separate from publishing. Supply feature-selected artifacts;
// this allowlist never copies the full SDK's runtime payload or launcher.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({ options: {
  out: { type: "string" }, target: { type: "string" },
  "local-binding": { type: "string" }, "remote-binding": { type: "string" },
  full: { type: "boolean", default: false },
} });
if (!values.out) throw new Error("--out is required");
const targets = {
  "darwin-arm64": ["darwin", "arm64"],
  "linux-x64-gnu": ["linux", "x64"],
  "linux-arm64-gnu": ["linux", "arm64"],
  "win32-x64-msvc": ["win32", "x64"],
  "win32-arm64-msvc": ["win32", "arm64"],
};
if (values.target && !targets[values.target]) throw new Error("unsupported --target");
if ((values["local-binding"] || values["remote-binding"]) && !values.target) throw new Error("native artifacts require --target");
const source = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const out = resolve(values.out);
const version = source.version;
async function manifest(directory, value) {
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, "package.json"), JSON.stringify({ version, license: source.license,
    repository: source.repository, engines: source.engines, ...value }, null, 2) + "\n");
}
const core = resolve(out, "core");
await access(resolve(root, "dist/index.js"));
await manifest(core, { name: "@microsandbox/core", type: "module", main: "./dist/index.js", types: "./dist/index.d.ts",
  exports: { ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
    "./provider": { types: "./dist/internal/provider.d.ts", import: "./dist/internal/provider.js" } },
  dependencies: source.dependencies, files: ["dist"] });
await cp(resolve(root, "dist"), resolve(core, "dist"), { recursive: true });
if (values.full) {
  const directory = resolve(out, "full");
  await manifest(directory, { ...source, workspaces: undefined, scripts: undefined, devDependencies: undefined,
    dependencies: { "@microsandbox/core": version },
    files: ["dist", "native/index.cjs", "native/index.d.ts", "bin/microsandbox.cjs", "README.md"] });
  await mkdir(resolve(directory, "dist"), { recursive: true });
  await mkdir(resolve(directory, "native"), { recursive: true });
  await mkdir(resolve(directory, "bin"), { recursive: true });
  for (const file of ["native/index.cjs", "native/index.d.ts", "bin/microsandbox.cjs", "README.md"]) {
    await cp(resolve(root, file), resolve(directory, file));
  }
  await cp(resolve(root, "dist/internal/resolve-binary.js"), resolve(directory, "dist/resolve-binary.js"));
  await writeFile(resolve(directory, "dist/index.js"), `import { createRequire } from 'node:module';
import { registerFullProvider } from '@microsandbox/core/provider';
import { msbPath } from './resolve-binary.js';
export * from '@microsandbox/core';
const require = createRequire(import.meta.url);
registerFullProvider(() => {
  const native = require('../native/index.cjs');
  const path = msbPath();
  if (path) native.setPackagedMsbPath(path);
  return native;
}, ${JSON.stringify(version)});
`);
  await writeFile(resolve(directory, "dist/index.d.ts"), "export * from '@microsandbox/core';\n");
}
for (const kind of ["local", "remote"]) {
  const directory = resolve(out, kind);
  const platformName = target => `@microsandbox/${kind}-${target}`;
  await manifest(directory, { name: `@microsandbox/${kind}`, type: "module",
    main: "./index.js", types: "./index.d.ts", files: ["index.js", "index.d.ts"],
    exports: { ".": { types: "./index.d.ts", import: "./index.js" } },
    dependencies: { "@microsandbox/core": version },
    optionalDependencies: Object.fromEntries(Object.keys(targets).map(target => [platformName(target), version])) });
  await writeFile(resolve(directory, "index.js"), `import { createRequire } from 'node:module';
import { registerProvider } from '@microsandbox/core/provider';
export * from '@microsandbox/core';
const require = createRequire(import.meta.url);
registerProvider(${JSON.stringify(kind)}, () => {
  const suffix = process.platform === 'linux' ? '-gnu' : process.platform === 'win32' ? '-msvc' : '';
  const target = process.platform + '-' + process.arch + suffix;
  if (!${JSON.stringify(Object.keys(targets))}.includes(target)) throw new Error('Unsupported microsandbox ${kind} platform: ' + target);
  return require('@microsandbox/${kind}-' + target);
}, ${JSON.stringify(version)});
`);
  await writeFile(resolve(directory, "index.d.ts"), "export * from '@microsandbox/core';\n");
  const artifact = values[`${kind}-binding`];
  if (artifact) {
    const target = values.target;
    const platform = resolve(out, `${kind}-${target}`);
    const [os, cpu] = targets[target];
    await manifest(platform, { name: platformName(target), main: `./microsandbox-${kind}.node`,
      os: [os], cpu: [cpu], ...(os === "linux" ? { libc: ["glibc"] } : {}),
      files: [`microsandbox-${kind}.node`] });
    await cp(resolve(artifact), resolve(platform, `microsandbox-${kind}.node`));
  }
}
console.log(`Staged SDK distributions in ${out}; no packages were published.`);
