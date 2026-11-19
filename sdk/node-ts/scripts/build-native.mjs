import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

// Keep the reviewed platform loader (including supported package names and
// diagnostics) while refreshing N-API's exported names and declaration file.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const loader = resolve(root, "native/index.cjs");
// Windows checkouts may use CRLF; locate the export line without changing either loader's bytes.
const boundary = /^module\.exports = nativeBinding\r?$/m;
const before = await readFile(loader, "utf8");
const split = before.search(boundary);
if (split < 0) throw new Error("Native loader export boundary is missing");
const require = createRequire(import.meta.url);
const manifestPath = require.resolve("@napi-rs/cli/package.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const cli = resolve(dirname(manifestPath), manifest.bin.napi);
const result = spawnSync(process.execPath, [cli, "build", ...process.argv.slice(2),
  "--platform", "--js", "index.cjs", "--dts", "index.d.ts", "--output-dir", "native"],
  { cwd: root, stdio: "inherit", env: process.env });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
const generated = await readFile(loader, "utf8");
const exports = generated.search(boundary);
if (exports < 0) throw new Error("Generated native exports are missing");
await writeFile(loader, before.slice(0, split) + generated.slice(exports));
