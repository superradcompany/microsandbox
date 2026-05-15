import { Sandbox } from "microsandbox";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = resolve(__dirname, "sample-images");
const rawPath = resolve(dataDir, "ext4-seeded.raw");
const qcow2Path = resolve(dataDir, "ext4-seeded.qcow2");

await using sandbox = await Sandbox.builder("volume-disk")
  .image("alpine")
  .volume("/seed", (m) => m.disk(rawPath).fstype("ext4").readonly())
  .volume("/data", (m) => m.disk(qcow2Path).fstype("ext4"))
  .replace()
  .create();

const seed = await sandbox.shell("cat /seed/hello.txt");
console.log(seed.stdout());

await sandbox.shell("echo 'written from sandbox' > /data/created.txt");
const back = await sandbox.shell("cat /data/created.txt");
console.log(back.stdout());
