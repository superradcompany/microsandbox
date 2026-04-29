import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("net-dns")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .network((n) =>
    n
      .denyDomains("blocked.example.com")
      .denyDomainSuffixes(".evil.com"),
  )
  .replace()
  .create();

const allowed = await sandbox.shell(
  "nslookup example.com 2>&1 | grep -c Address || echo 0",
);
console.log(`example.com: ${allowed.stdout().trim()} address(es)`);

const blocked = await sandbox.shell(
  "nslookup blocked.example.com 2>&1 && echo RESOLVED || echo BLOCKED",
);
console.log(`blocked.example.com: ${lastLine(blocked.stdout().trim())}`);

const suffix = await sandbox.shell(
  "nslookup anything.evil.com 2>&1 && echo RESOLVED || echo BLOCKED",
);
console.log(`anything.evil.com: ${lastLine(suffix.stdout().trim())}`);

const unrelated = await sandbox.shell(
  "nslookup cloudflare.com 2>&1 | grep -c Address || echo 0",
);
console.log(`cloudflare.com: ${unrelated.stdout().trim()} address(es)`);


function lastLine(s: string): string {
  const lines = s.split("\n");
  return lines[lines.length - 1] || s;
}
