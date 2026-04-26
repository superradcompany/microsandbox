import { Sandbox, Mount } from "microsandbox";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const dataDir = resolve(__dirname, "..", "..", "volume-disk-data");
  const rawPath = resolve(dataDir, "ext4-seeded.raw");
  const qcow2Path = resolve(dataDir, "ext4-seeded.qcow2");

  console.log("Mounting:");
  console.log(`  /seed (raw, ro) <- ${rawPath}`);
  console.log(`  /data (qcow2, rw) <- ${qcow2Path}`);

  const sandbox = await Sandbox.create({
    name: "volume-disk",
    image: "alpine",
    volumes: {
      "/seed": Mount.disk(rawPath, { format: "raw", fstype: "ext4", readonly: true }),
      "/data": Mount.disk(qcow2Path, { format: "qcow2", fstype: "ext4" }),
    },
    replace: true,
  });

  // Verify the read-only seed mount.
  console.log("\n=== /seed (read-only) ===");
  const listing = await sandbox.shell("ls -la /seed");
  process.stdout.write(listing.stdout());

  const hello = await sandbox.shell("cat /seed/hello.txt");
  console.log(`hello.txt: ${hello.stdout().trim()}`);

  const release = await sandbox.shell("cat /seed/notes/release.txt");
  console.log(`notes/release.txt: ${release.stdout().trim()}`);

  const manifest = await sandbox.shell("cat /seed/lib/data.json");
  console.log(`lib/data.json:\n${manifest.stdout()}`);

  // Confirm writes are blocked on the read-only mount.
  const blocked = await sandbox.shell("touch /seed/should-fail 2>&1 || true");
  console.log(`attempted /seed write -> ${blocked.stdout().trim()}`);

  // Demonstrate writes to the writable qcow2 mount.
  console.log("\n=== /data (read-write) ===");
  await sandbox.shell("echo 'written from inside the sandbox' > /data/created.txt");
  const readback = await sandbox.shell("cat /data/created.txt");
  console.log(`created.txt: ${readback.stdout().trim()}`);

  const qcowHello = await sandbox.shell("cat /data/hello.txt");
  console.log(`hello.txt: ${qcowHello.stdout().trim()}`);

  await sandbox.stopAndWait();
  console.log("\nSandbox stopped.");
}

main();
