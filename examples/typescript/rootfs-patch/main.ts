import { Sandbox } from "microsandbox";

console.log("Creating sandbox with rootfs patches (image=alpine)");

await using sandbox = await Sandbox.builder("rootfs-patch")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .patch((p) =>
    p
      .text("/etc/greeting.txt", "Hello from a patched rootfs!\n")
      .text("/etc/motd", "Welcome to a patched microsandbox.\n", { replace: true })
      .mkdir("/app", { mode: 0o755 })
      .text("/app/config.json", '{"version": "1.0", "debug": true}', { mode: 0o644 })
      .append("/etc/hosts", "127.0.0.1 myapp.local\n"),
  )
  .replace()
  .create();

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
