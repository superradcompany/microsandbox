// Import the in-tree build so this live example always exercises the current checkout's native module.
import { Sandbox, SandboxReplacedError } from "../../../sdk/node-ts/dist/index.js";

const name = process.env.MSB_E2E_NAME ?? `lifecycle-typescript-${process.pid}`;
const image = process.env.MSB_E2E_IMAGE ?? "alpine:3.19";
const platform = process.env.MSB_E2E_PLATFORM ?? `${process.platform}-${process.arch}`;
const timings: Record<string, number> = {};
const total = performance.now();

async function measured<T>(label: string, operation: () => Promise<T>): Promise<T> {
  const started = performance.now();
  const value = await operation();
  timings[label] = performance.now() - started;
  return value;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function readMarker(sandbox: Sandbox): Promise<string> {
  const output = await sandbox.shell("printf '%s' \"$LIFECYCLE_MARKER\"");
  assert(output.success, `marker exec failed with code ${output.code}`);
  return output.stdout();
}

async function cleanup(): Promise<void> {
  try {
    const current = await Sandbox.get(name);
    await current.destroy({ force: true, timeoutMs: 5_000 });
  } catch {
    // The unique example sandbox normally does not exist before or after a run.
  }
}

await cleanup();

try {
  const created = await measured("find_or_create_new", () =>
    Sandbox.builder(name)
      .image(image)
      .cpus(1)
      .memory(256)
      .env("LIFECYCLE_MARKER", "original")
      .findOrCreate(),
  );
  const originalId = created.id;

  const reused = await measured("find_or_create_existing", () =>
    Sandbox.builder(name)
      .image(image)
      .memory(768)
      .env("LIFECYCLE_MARKER", "ignored")
      .findOrCreate(),
  );
  assert(reused.id === originalId, "findOrCreate changed the persisted identity");
  assert((await readMarker(reused)) === "original", "existing configuration did not win");

  const handle = await Sandbox.get(name);
  const connected = await measured("connect_or_start", () => handle.connectOrStart());
  assert(connected.id === originalId, "connectOrStart changed the persisted identity");

  await measured("wait_for_running", () => connected.waitForStatus("running"));
  await measured("exec", async () => {
    assert((await readMarker(connected)) === "original", "exec observed the wrong config");
  });

  const restarted = await measured("restart", () => connected.restart());
  assert(restarted.id === originalId, "restart changed the persisted identity");
  assert((await readMarker(restarted)) === "original", "restart lost persisted configuration");

  const stale = await Sandbox.get(name);
  await measured("destroy_original", () => restarted.destroy());
  const replacement = await Sandbox.builder(name)
    .image(image)
    .cpus(1)
    .memory(256)
    .env("LIFECYCLE_MARKER", "replacement")
    .findOrCreate();
  assert(replacement.id !== originalId, "replacement reused the destroyed identity");

  await measured("stale_identity_rejection", async () => {
    try {
      await stale.destroy();
      throw new Error("stale receiver acted on the replacement");
    } catch (error) {
      if (!(error instanceof SandboxReplacedError)) throw error;
    }
  });
  assert((await readMarker(replacement)) === "replacement", "stale receiver harmed replacement");
  await measured("destroy_replacement", () => replacement.destroy());
  timings.total = performance.now() - total;

  console.log(
    "MSB_LIFECYCLE_METRICS " +
      JSON.stringify({
        sdk: "typescript",
        platform,
        sandbox: name,
        identity: originalId,
        checks: 10,
        timings_ms: timings,
        result: "pass",
      }),
  );
} catch (error) {
  await cleanup();
  throw error;
}
