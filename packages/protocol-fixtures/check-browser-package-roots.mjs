import { builtinModules, createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

// This checks browser export resolution and execution without Node globals.
// It does not replace a browser/WebSocket integration test.
const self = fileURLToPath(import.meta.url);
if (process.argv[2] === "--evaluate") {
  const { SourceTextModule, createContext } = await import("node:vm");
  const context = createContext({
    console, TextEncoder, TextDecoder, AbortController, AbortSignal,
    DOMException, performance, setTimeout, clearTimeout, queueMicrotask,
  });
  const module = new SourceTextModule(readFileSync(process.argv[3], "utf8"), { context });
  await module.link(specifier => { throw new Error(`Unexpected unbundled browser import: ${specifier}`); });
  await module.evaluate({ timeout: 15_000 });
  if (!context.packageRoots || context.process || context.Buffer || context.require) throw new Error("Browser execution context was not isolated from Node globals");
  for (const [name, value] of Object.entries(context.packageRoots)) {
    if (typeof value.Client !== "function") throw new Error(`Missing generic client export from ${name}`);
  }
  console.log("All three packed package roots loaded and the external protocol ran without Node builtins or globals.");
} else {
  const consumer = process.argv[2];
  if (!consumer) throw new Error("Usage: node check-browser-package-roots.mjs <compiled-consumer-directory>");
  const output = path.resolve(consumer);
  const entry = path.join(output, "browser-roots.mjs");
  const bundleFile = path.join(output, "browser-bundle.mjs");
  writeFileSync(entry, `
import * as generic from "@microsandbox/protocol-client";
import * as agent from "@microsandbox/agent-client";
import * as control from "@microsandbox/control-client";
import "./consumer.js";
globalThis.packageRoots = { generic, agent, control };
const codec = new generic.CborEnvelopeCodec();
const body = codec.encode(1, "custom.browser", codec.encodePayload({ value: 9007199254740993n }));
const frame = codec.decode({id:1,flags:1,body});
if (frame.decodePayload().value !== 9007199254740993n) throw new Error("Browser CBOR lost integer precision");
if (new control.SetMemoryTarget(control.MiB(2048)).message().kind !== "encoded") throw new Error("Control request could not be constructed");
`);
  const require = createRequire(path.join(path.dirname(self), "../protocol-client/typescript/package.json"));
  const { rolldown } = await import(pathToFileURL(require.resolve("rolldown")).href);
  const builtins = new Set(builtinModules.map(name => name.replace(/^node:/, "")));
  const build = await rolldown({
    input: entry, platform: "browser", treeshake: false,
    plugins: [{
      name: "reject-node-builtins",
      resolveId(source) {
        if (source.startsWith("node:") || builtins.has(source)) throw new Error(`Browser root imports Node builtin ${source}`);
      },
    }],
    onwarn(warning) { throw new Error(warning.message); },
  });
  try {
    const result = await build.write({ file: bundleFile, format: "es" });
    const chunks = result.output.filter(output => output.type === "chunk");
    if (chunks.length !== 1 || chunks[0].imports.length || chunks[0].dynamicImports.length) throw new Error("Browser fixture is not a self-contained bundle");
    writeFileSync(path.join(output, "browser-module-inventory.json"), JSON.stringify(Object.keys(chunks[0].modules).sort(), null, 2) + "\n");
  } finally { await build.close(); }
  const run = spawnSync(process.execPath, ["--experimental-vm-modules", self, "--evaluate", bundleFile], { encoding: "utf8", timeout: 20_000 });
  process.stdout.write(run.stdout ?? ""); process.stderr.write(run.stderr ?? "");
  if (run.error) throw run.error;
  if (run.status !== 0) process.exitCode = run.status ?? 1;
  console.log(`Browser package evidence retained in ${output}`);
}
