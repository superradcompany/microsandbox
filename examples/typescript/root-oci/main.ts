import { Sandbox } from "microsandbox";

async function main() {
  console.log("Creating sandbox (image=alpine)");

  // Create a sandbox with an OCI image rootfs.
  const sandbox = await Sandbox.create({
    name: "oci-root",
    image: "alpine",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  // Run a command.
  const output = await sandbox.shell("echo 'Hello from microsandbox!'");
  console.log("stdout:", output.stdout());
  console.log("stderr:", output.stderr());
  console.log("exit code:", output.code);

  // Run a few more commands.
  const uname = await sandbox.shell("uname -a");
  console.log("uname:", uname.stdout());

  const osRelease = await sandbox.shell("cat /etc/os-release");
  console.log("os-release:\n" + osRelease.stdout());

  // Stop the sandbox gracefully.
  await sandbox.stopAndWait();

  console.log("Sandbox stopped.");
}

main();
