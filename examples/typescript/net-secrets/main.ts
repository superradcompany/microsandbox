import { Sandbox } from "microsandbox";

// Secret with placeholder substitution and host allowlist. The 3-arg
// shorthand auto-generates the placeholder as `$MSB_API_KEY`.
await using sandbox = await Sandbox.builder("net-secrets")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .secretEnv("API_KEY", "sk-real-secret-123", "example.com")
  .replace()
  .create();

// 1. Env var auto-set — guest only sees the placeholder.
const env = await sandbox.shell("echo $API_KEY");
console.log(`Guest env: API_KEY=${env.stdout().trim()}`);

// 2. HTTPS to allowed host — proxy substitutes secret, request succeeds.
const allowed = await sandbox.shell(
  "wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL",
);
console.log(`HTTPS to example.com (allowed): ${allowed.stdout().trim()}`);

// 3. HTTPS to disallowed host WITH placeholder in header — BLOCKED.
const blocked = await sandbox.shell(
  "wget -q -O /dev/null --timeout=5 --header='Authorization: Bearer $MSB_API_KEY' https://cloudflare.com 2>&1 && echo OK || echo BLOCKED",
);
const lines = blocked.stdout().trim().split("\n");
console.log(
  `HTTPS to cloudflare.com with placeholder (disallowed): ${lines[lines.length - 1]}`,
);
