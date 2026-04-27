import { NetworkPolicy, Sandbox } from "microsandbox";

const REQ =
  "wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL";

// 1. Default (public-only) — public internet works.
{
  await using sb = await Sandbox.builder("net-policy-public")
    .image("alpine")
    .cpus(1)
    .memory(512)
    .replace()
    .create();
  console.log(`Public-only → HTTP: ${(await sb.shell(REQ)).stdout().trim()}`);
}

// 2. Allow-all — everything reachable.
{
  await using sb = await Sandbox.builder("net-policy-all")
    .image("alpine")
    .cpus(1)
    .memory(512)
    .network((n) => n.policy(NetworkPolicy.allowAll()))
    .replace()
    .create();
  console.log(`Allow-all → HTTP: ${(await sb.shell(REQ)).stdout().trim()}`);
}

// 3. No network — all connections denied.
{
  await using sb = await Sandbox.builder("net-policy-none")
    .image("alpine")
    .cpus(1)
    .memory(512)
    .network((n) => n.policy(NetworkPolicy.none()))
    .replace()
    .create();
  console.log(`None → HTTP: ${(await sb.shell(REQ)).stdout().trim()}`);
}

// Cleanup.
await Sandbox.remove("net-policy-public");
await Sandbox.remove("net-policy-all");
await Sandbox.remove("net-policy-none");
