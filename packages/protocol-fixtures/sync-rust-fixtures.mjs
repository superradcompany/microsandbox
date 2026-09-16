import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Cargo cannot include files outside a crate. Keep its test fixtures identical
// to the shared corpus; default to checking so validation never rewrites bytes.
const root = fileURLToPath(new URL("../../", import.meta.url));
const copies = [
  ["packages/protocol-fixtures/control-v1.json", "crates/protocol/tests/fixtures/control-v1.json"],
  ...[
    "crates/protocol/tests/fixtures/legacy_control_records.rs",
    "crates/runtime/tests/fixtures/legacy_control_records.rs",
    "packages/control-client/rust/tests/fixtures/legacy_control_records.rs",
  ].map(destination => ["packages/protocol-fixtures/legacy-json/control_records.rs", destination]),
];
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--write")) {
  throw new Error("Usage: node sync-rust-fixtures.mjs [--write]");
}
const write = args[0] === "--write";
for (const [source, destination] of copies) {
  const bytes = readFileSync(path.join(root, source));
  const output = path.join(root, destination);
  if (write) {
    mkdirSync(path.dirname(output), { recursive: true });
    writeFileSync(output, bytes);
  } else if (!readFileSync(output).equals(bytes)) {
    throw new Error(`${destination} differs from ${source}; review the change, then run with --write`);
  }
}
console.log(`${write ? "Copied" : "Verified"} ${copies.length} exact Rust fixture copies.`);
