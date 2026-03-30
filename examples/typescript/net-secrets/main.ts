import { Sandbox, Secret } from "microsandbox";

async function main() {
  // Secret configured via Secret.env(). TLS interception auto-enabled.
  // Placeholder auto-generated as $MSB_API_KEY.
  const sandbox = await Sandbox.create({
    name: "net-secrets",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    secrets: [
      Secret.env("API_KEY", { value: "sk-real-secret-123", allowHosts: ["example.com"] }),
    ],
    replace: true,
  });

  // 1. Env var auto-set — guest only sees the placeholder.
  const env = await sandbox.shell("echo $API_KEY");
  const placeholder = env.stdout().trim();
  console.log(`Guest env: API_KEY=${placeholder}`);

  // 2. HTTPS to allowed host — proxy substitutes secret, request succeeds.
  const allowed = await sandbox.shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL");
  console.log(`HTTPS to example.com (allowed): ${allowed.stdout().trim()}`);

  // 3. HTTPS to disallowed host WITH placeholder in header — BLOCKED.
  const blocked = await sandbox.shell(
    "wget -q -O /dev/null --timeout=5 --header='Authorization: Bearer $MSB_API_KEY' https://cloudflare.com 2>&1 && echo OK || echo BLOCKED"
  );
  const lines = blocked.stdout().trim().split("\n");
  console.log(`HTTPS to cloudflare.com with placeholder (disallowed): ${lines[lines.length - 1]}`);

  await sandbox.stopAndWait();
  await Sandbox.remove("net-secrets");
}

main();
