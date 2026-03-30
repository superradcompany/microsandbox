import { Sandbox } from "microsandbox";

async function main() {
  // 1. Default (public-only) — public internet works.
  const publicOnly = await Sandbox.create({
    name: "net-policy-public",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  let output = await publicOnly.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL");
  console.log(`Public-only → HTTP: ${output.stdout().trim()}`);
  await publicOnly.stopAndWait();

  // 2. Allow-all — everything reachable, including private networks.
  const allowAll = await Sandbox.create({
    name: "net-policy-all",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    network: { policy: "allow-all" },
    replace: true,
  });

  output = await allowAll.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL");
  console.log(`Allow-all → HTTP: ${output.stdout().trim()}`);
  await allowAll.stopAndWait();

  // 3. No network — all connections denied.
  const noNet = await Sandbox.create({
    name: "net-policy-none",
    image: "alpine:latest",
    cpus: 1,
    memoryMib: 512,
    network: { policy: "none" },
    replace: true,
  });

  output = await noNet.shell("wget -q -O /dev/null --timeout=3 http://example.com && echo OK || echo BLOCKED");
  console.log(`None → HTTP: ${output.stdout().trim()}`);
  await noNet.stopAndWait();

  // Cleanup.
  await Sandbox.remove("net-policy-public");
  await Sandbox.remove("net-policy-all");
  await Sandbox.remove("net-policy-none");
}

main();
