import { Sandbox } from "microsandbox";

console.log("Creating sandbox (image=alpine)");

await using sandbox = await Sandbox.builder("attach-example")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

console.log("Attaching to shell (press Ctrl+] to detach)...");

const exitCode = await sandbox.attachShell();
console.log(`Shell exited with code ${exitCode}`);
