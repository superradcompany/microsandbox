import { Sandbox } from "microsandbox";
import { arch } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const cpuArch = arch() === "arm64" ? "aarch64" : "x86_64";
const imagePath = resolve(__dirname, "qcow2-alpine", `${cpuArch}.qcow2`);
console.log(`Creating sandbox (image=${imagePath})`);

await using sandbox = await Sandbox.builder("block-root")
  .image(imagePath)
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
