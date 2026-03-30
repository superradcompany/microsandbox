import { Sandbox } from "microsandbox";

async function main() {
  console.log("Creating sandbox with rootfs patches (image=alpine:latest)");

  const sandbox = await Sandbox.create({
    name: "rootfs-patch",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    replace: true,
    patches: [
      { kind: "text", path: "/etc/greeting.txt", content: "Hello from a patched rootfs!\n" },
      { kind: "text", path: "/etc/motd", content: "Welcome to a patched microsandbox.\n", replace: true },
      { kind: "mkdir", path: "/app", mode: 0o755 },
      { kind: "text", path: "/app/config.json", content: '{"version": "1.0", "debug": true}', mode: 0o644 },
      { kind: "append", path: "/etc/hosts", content: "127.0.0.1 myapp.local\n" },
    ],
  });

  // Verify the patches were applied.
  const greeting = await sandbox.shell("cat /etc/greeting.txt");
  console.log(`greeting: ${greeting.stdout().trimEnd()}`);

  const motd = await sandbox.shell("cat /etc/motd");
  console.log(`motd: ${motd.stdout().trimEnd()}`);

  const config = await sandbox.shell("cat /app/config.json");
  console.log(`config: ${config.stdout().trimEnd()}`);

  const hosts = await sandbox.shell("grep myapp.local /etc/hosts");
  console.log(`hosts entry: ${hosts.stdout().trimEnd()}`);

  const perms = await sandbox.shell("stat -c '%a' /app");
  console.log(`/app permissions: ${perms.stdout().trimEnd()}`);

  await sandbox.stopAndWait();
  console.log("Sandbox stopped.");
}

main();
