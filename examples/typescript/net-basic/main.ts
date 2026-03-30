import { Sandbox } from "microsandbox";

async function main() {
  const sandbox = await Sandbox.create({
    name: "net-basic",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  // DNS resolution.
  const dns = await sandbox.shell("nslookup example.com 2>&1 | head -8");
  console.log("DNS:\n" + dns.stdout());

  // HTTP fetch.
  const http = await sandbox.shell("wget -q -O - http://example.com 2>&1 | head -3");
  console.log("HTTP:\n" + http.stdout());

  // Interface status.
  const iface = await sandbox.shell("ip addr show eth0");
  console.log("Interface:\n" + iface.stdout());

  await sandbox.stopAndWait();
}

main();
