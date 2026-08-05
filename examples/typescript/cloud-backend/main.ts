import {
  Sandbox,
  defaultBackendKind,
} from "microsandbox";

function configureCloudBackend() {
  if (defaultBackendKind() !== "cloud") {
    throw new Error(
      "set MSB_BACKEND=cloud with MSB_API_KEY, or select a cloud profile",
    );
  }
}

async function waitUntilStopped(name: string) {
  for (let i = 0; i < 30; i += 1) {
    const handle = await Sandbox.get(name);
    if (handle.status === "stopped") return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`sandbox ${name} did not stop within 30s`);
}

configureCloudBackend();

const name = `typescript-cloud-${Math.floor(Date.now() / 1000)}`;
console.log(`creating ${name} on the cloud backend`);

const sandbox = await Sandbox.builder(name)
  .image("alpine:3.19")
  .cpus(1)
  .memory(512)
  .entrypoint([
    "/bin/sh",
    "-lc",
    "for i in 1 2 3; do echo typescript-cloud-$i; sleep 1; done",
  ])
  .maxDuration(60)
  .replace()
  .create();

try {
  const output = await sandbox.shell(
    "printf 'cloud exec from typescript\\n'; uname -m",
  );
  console.log(`exec status: ${output.status.code}`);
  process.stdout.write(output.stdout());

  const stream = await sandbox.logStream({
    sources: ["stdout", "stderr", "system"],
    follow: true,
  });
  try {
    for (let i = 0; i < 3; i += 1) {
      const entry = await recvWithTimeout(stream, 20_000);
      if (!entry) break;
      console.log(
        `[${entry.timestamp.toISOString()} ${entry.source}] ${entry.text().trimEnd()}`,
      );
    }
  } finally {
    await stream[Symbol.asyncDispose]();
  }
} finally {
  await sandbox.stop();
  await waitUntilStopped(name);
  await Sandbox.remove(name);
  console.log(`removed ${name}`);
}

async function recvWithTimeout(
  stream: Awaited<ReturnType<Sandbox["logStream"]>>,
  timeoutMs: number,
) {
  const timedOut = Symbol("timed out");
  const timeout = new Promise<typeof timedOut>((resolve) =>
    setTimeout(() => resolve(timedOut), timeoutMs),
  );
  const entry = await Promise.race([stream.recv(), timeout]);
  if (entry === timedOut) {
    console.log("timed out waiting for another log entry");
    return null;
  }
  return entry;
}
