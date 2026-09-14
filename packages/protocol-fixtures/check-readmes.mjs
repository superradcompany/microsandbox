import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Compile complete README examples against the built, exported declarations.
// Virtual source files keep documentation checks from writing into the packages.
const packages = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let checked = 0;
for (const name of ["protocol-client", "agent-client", "control-client"]) {
  const directory = path.join(packages, name, "typescript");
  const require = createRequire(path.join(directory, "package.json"));
  const ts = require("typescript");
  const readme = readFileSync(path.join(directory, "README.md"), "utf8");
  for (const [index, match] of [...readme.matchAll(/```ts\n([\s\S]*?)\n```/g)].entries()) {
    const filename = path.join(directory, `readme-example-${index + 1}.ts`);
    const options = {
      target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext, noEmit: true,
      strict: true, noUncheckedIndexedAccess: true, skipLibCheck: true,
      lib: ["lib.es2023.d.ts", "lib.dom.d.ts"],
    };
    const host = ts.createCompilerHost(options);
    const originalRead = host.readFile.bind(host), originalExists = host.fileExists.bind(host);
    // TypeScript uses forward slashes even when path.join produces Windows separators.
    const canonical = name => host.getCanonicalFileName(path.normalize(name));
    const isExample = name => canonical(name) === canonical(filename);
    host.readFile = name => isExample(name) ? match[1] : originalRead(name);
    host.fileExists = name => isExample(name) || originalExists(name);
    const diagnostics = ts.getPreEmitDiagnostics(ts.createProgram([filename], options, host));
    if (diagnostics.length) {
      process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
        getCurrentDirectory: () => directory, getCanonicalFileName: name => name, getNewLine: () => "\n",
      }));
      process.exitCode = 1;
    }
    checked++;
  }
}
if (!process.exitCode) console.log(`Typechecked ${checked} public README examples.`);
