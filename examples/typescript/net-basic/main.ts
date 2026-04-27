import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("net-basic")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

const dns = await sandbox.shell("nslookup example.com 2>&1 | head -8");
console.log("DNS:\n" + dns.stdout());

const http = await sandbox.shell("wget -q -O - http://example.com 2>&1 | head -3");
console.log("HTTP:\n" + http.stdout());

const iface = await sandbox.shell("ip addr show eth0");
console.log("Interface:\n" + iface.stdout());
