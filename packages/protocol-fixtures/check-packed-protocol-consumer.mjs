import { lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Supply an external directory containing npm-installed package tarballs.
// Keeping the fixture there prevents workspace/self-reference resolution from
// hiding missing exports or declarations in the installed package.
const consumer = process.argv[2];
if (!consumer) throw new Error("Usage: node check-packed-protocol-consumer.mjs <installed-consumer-directory>");
const fixtures = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(fixtures, "../protocol-client/typescript/package.json"));
const ts = require("typescript");
const installed = path.join(path.resolve(consumer), "node_modules/@microsandbox/protocol-client");
if (lstatSync(installed).isSymbolicLink()) throw new Error("Consumer must install a package, not a workspace symlink");
const installedRoot = realpathSync(installed);
if (path.relative(realpathSync(consumer), installedRoot) !== "node_modules/@microsandbox/protocol-client") throw new Error("Installed declarations must remain inside the external consumer directory");
const lock = JSON.parse(readFileSync(path.join(consumer, "package-lock.json"), "utf8"));
const entry = lock.packages?.["node_modules/@microsandbox/protocol-client"];
if (!entry?.integrity || !entry.resolved?.endsWith(".tgz")) throw new Error("Consumer lockfile must identify an installed package tarball and integrity");
const output = mkdtempSync(path.join(path.resolve(consumer), "protocol-consumer-"));
const source = path.join(output, "consumer.ts");
writeFileSync(path.join(output, "package.json"), JSON.stringify({ type: "module", private: true }));
writeFileSync(source, readFileSync(path.join(fixtures, "consumer-typescript.ts")));
const options = {
  target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext, strict: true,
  noUncheckedIndexedAccess: true, types: [], lib: ["lib.es2023.d.ts", "lib.dom.d.ts"],
};
const program = ts.createProgram([source], options);
const declaration = program.getSourceFiles().find(file => realpathSync(file.fileName) === path.join(installedRoot, "dist/index.d.ts"));
if (!declaration) throw new Error("Consumer did not resolve the installed public declarations");
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length) {
  process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => output, getCanonicalFileName: name => name, getNewLine: () => "\n",
  }));
  process.exitCode = 1;
} else {
  const emitted = program.emit();
  if (emitted.emitSkipped) throw new Error("Consumer emit was skipped");
  const run = spawnSync(process.execPath, [path.join(output, "consumer.js")], { encoding: "utf8", timeout: 15_000 });
  process.stdout.write(run.stdout ?? ""); process.stderr.write(run.stderr ?? "");
  if (run.error) throw run.error;
  if (run.status !== 0) process.exitCode = run.status ?? 1;
}
console.log(`Consumer evidence retained in ${output}`);
