import { LogEntry, Sandbox } from "microsandbox";

console.log("Creating sandbox (image=alpine)");

const sandbox = await Sandbox.builder("logs-read")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

console.log("Running a small shell script to generate output");
await sandbox.shell(
  "echo line one; echo line two; echo error line 1>&2; echo line three"
);

// Stop the sandbox so we read a closed log. exec.log persists on disk.
await sandbox.stopAndWait();

const handle = await Sandbox.get("logs-read");

// Default sources: stdout + stderr + output (user-program output).
const entries = await handle.logs();
console.log(
  `\n== default sources (stdout+stderr+output): ${entries.length} entries`
);
for (const e of entries) printEntry(e);

// Include system markers + runtime/kernel diagnostics.
const withSystem = await handle.logs({
  sources: ["stdout", "stderr", "output", "system"],
});
console.log(
  `\n== including system (runtime/kernel + lifecycle markers): ${withSystem.length} entries`
);

// Tail the last entry.
const tail = await handle.logs({ tail: 1 });
console.log(`\n== tail=1: ${tail.length} entries`);
if (tail.length > 0) printEntry(tail[0]);

function printEntry(e: LogEntry) {
  const id =
    e.sessionId !== null
      ? `id=${String(e.sessionId).padStart(3, " ")}`
      : "id=---";
  console.log(
    `  [${e.timestamp.toISOString()}] ${id} ${e.source}: ${e.text().trimEnd()}`
  );
}
