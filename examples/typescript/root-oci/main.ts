import { Sandbox } from "microsandbox";

console.log("Creating sandbox (image=alpine)");

await using sandbox = await Sandbox.builder("oci-root")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

const output = await sandbox.shell("echo 'Hello from microsandbox!'");
console.log("stdout:", output.stdout());
console.log("stderr:", output.stderr());
console.log("exit code:", output.code);

const uname = await sandbox.shell("uname -a");
console.log("uname:", uname.stdout());

const osRelease = await sandbox.shell("cat /etc/os-release");
console.log("os-release:\n" + osRelease.stdout());
