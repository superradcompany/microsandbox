import { Sandbox } from "microsandbox";

async function main() {
  const sandbox = await Sandbox.create({
    name: "net-dns",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    network: {
      blockDomains: ["blocked.example.com"],
      blockDomainSuffixes: [".evil.com"],
    },
    replace: true,
  });

  // Allowed domain resolves normally.
  const allowed = await sandbox.shell("nslookup example.com 2>&1 | grep -c Address || echo 0");
  console.log(`example.com: ${allowed.stdout().trim()} address(es)`);

  // Exact-match blocked domain fails.
  const blocked = await sandbox.shell("nslookup blocked.example.com 2>&1 && echo RESOLVED || echo BLOCKED");
  console.log(`blocked.example.com: ${lastLine(blocked.stdout().trim())}`);

  // Suffix-match blocked domain fails.
  const suffix = await sandbox.shell("nslookup anything.evil.com 2>&1 && echo RESOLVED || echo BLOCKED");
  console.log(`anything.evil.com: ${lastLine(suffix.stdout().trim())}`);

  // Unrelated domain still works.
  const unrelated = await sandbox.shell("nslookup cloudflare.com 2>&1 | grep -c Address || echo 0");
  console.log(`cloudflare.com: ${unrelated.stdout().trim()} address(es)`);

  await sandbox.stopAndWait();
  await Sandbox.remove("net-dns");
}

function lastLine(s: string): string {
  const lines = s.split("\n");
  return lines[lines.length - 1] || s;
}

main();
