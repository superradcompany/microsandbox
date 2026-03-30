import { Sandbox } from "microsandbox";
import { arch } from "os";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const cpuArch = arch() === "arm64" ? "aarch64" : "x86_64";
  const rootfsPath = resolve(__dirname, "rootfs-alpine", cpuArch);
  console.log(`Creating sandbox (rootfs=${rootfsPath})`);

  // Create a sandbox with a bind-mounted rootfs.
  const sandbox = await Sandbox.create({
    name: "bind-root",
    image: rootfsPath,
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
