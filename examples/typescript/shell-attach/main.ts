import { Sandbox } from "microsandbox";

async function main() {
  console.log("Creating sandbox (image=alpine)");

  const sandbox = await Sandbox.create({
    name: "attach-example",
    image: "alpine",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  console.log("Attaching to shell (press Ctrl+] to detach)...");

  const exitCode = await sandbox.attachShell();
  console.log(`Shell exited with code ${exitCode}`);

  await sandbox.stopAndWait();
  console.log("Sandbox stopped.");
}

main();
