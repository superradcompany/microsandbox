import { Sandbox } from "microsandbox";

console.log("Connecting to or creating sandbox (image=alpine on first creation)");

// An interactive workspace is useful across runs. Builder options seed only the first creation;
// later runs reconnect to the persisted sandbox and preserve its files and configuration.
await using sandbox = await Sandbox.builder("attach-example")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .connectOrCreate();

console.log("Attaching to shell (press Ctrl+] to detach)...");

const exitCode = await sandbox.attachShell();
console.log(`Shell exited with code ${exitCode}`);
