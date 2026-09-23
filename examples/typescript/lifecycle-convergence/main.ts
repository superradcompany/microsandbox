// Import the in-tree build so this live example always exercises the current checkout's native module.
import { Sandbox, SandboxReplacedError } from "../../../sdk/node-ts/dist/index.js";

const name = process.env.MSB_E2E_NAME ?? `lifecycle-typescript-${process.pid}`;
const raceName = `${name}-race`;
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

async function cleanup(target = name): Promise<void> {
  try {
    const current = await Sandbox.get(target);
    await current.destroy({ force: true, timeoutMs: 5_000 });
  } catch {
    // The unique example sandbox normally does not exist before or after a run.
  }
}

async function runConcurrencyChecks(): Promise<void> {
  await cleanup(raceName);
  const candidates = ["candidate-0", "candidate-1", "candidate-2", "candidate-3"];
  const raced = await measured("concurrent_connect_or_create", () =>
    Promise.all(
      candidates.map((marker) =>
        Sandbox.builder(raceName)
          .image(image)
          .cpus(1)
          .memory(256)
          .env("LIFECYCLE_MARKER", marker)
          .connectOrCreate(),
      ),
    ),
  );
  const raceId = raced[0].id;
  assert(
    raced.every((sandbox) => sandbox.id === raceId),
    "concurrent connectOrCreate callers selected different identities",
  );
  const marker = await readMarker(raced[0]);
  assert(candidates.includes(marker), `concurrent creation persisted unexpected marker ${marker}`);

  await raced[0].stop();
  const handles = await Promise.all(candidates.map(() => Sandbox.get(raceName)));
  const connected = await measured("concurrent_connect_or_start", () =>
    Promise.all(handles.map((handle) => handle.connectOrStart())),
  );
  assert(
    connected.every((sandbox) => sandbox.id === raceId),
    "concurrent connectOrStart callers selected different identities",
  );
  assert((await readMarker(connected[0])) === marker, "start race lost persisted configuration");

  await connected[0].stop();
  const detached = await measured("connect_or_start_detached", async () =>
    (await Sandbox.get(raceName)).connectOrStart({ detached: true }),
  );
  assert(
    detached.id === raceId && !detached.ownsLifecycle,
    "detached connectOrStart changed identity or took lifecycle ownership",
  );

  const forced = await measured("restart_force", () =>
    detached.restart({ force: true, timeoutMs: 5_000 }),
  );
  assert(
    forced.id === raceId && forced.ownsLifecycle,
    "forced restart changed identity or failed to return an attached handle",
  );
  assert((await readMarker(forced)) === marker, "forced restart lost persisted configuration");

  const detachedRestart = await measured("restart_detached_timeout", () =>
    forced.restart({ timeoutMs: 3_000, detached: true }),
  );
  assert(
    detachedRestart.id === raceId && !detachedRestart.ownsLifecycle,
    "detached restart changed identity or took lifecycle ownership",
  );
  assert(
    (await readMarker(detachedRestart)) === marker,
    "detached restart lost persisted configuration",
  );
  await measured("destroy_force_timeout", () =>
    detachedRestart.destroy({ force: true, timeoutMs: 5_000 }),
  );
}

await cleanup();
await cleanup(raceName);

try {
  await runConcurrencyChecks();
  const created = await measured("connect_or_create_new", () =>
    Sandbox.builder(name)
      .image(image)
      .cpus(1)
      .memory(256)
      .env("LIFECYCLE_MARKER", "original")
      .connectOrCreate(),
  );
  const originalId = created.id;

  const reused = await measured("connect_or_create_existing", () =>
    Sandbox.builder(name)
      .image(image)
      .memory(768)
      .env("LIFECYCLE_MARKER", "ignored")
      .connectOrCreate(),
  );
  assert(reused.id === originalId, "connectOrCreate changed the persisted identity");
  assert((await readMarker(reused)) === "original", "existing configuration did not win");

  // Strict start resumes an existing stopped identity without accepting creation options.
  await reused.stop();
  const resumed = await measured("start", () => Sandbox.start(name));
  assert(resumed.id === originalId, "start changed the persisted identity");
  assert((await readMarker(resumed)) === "original", "start lost persisted configuration");

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
    .connectOrCreate();
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
        checks: 17,
        timings_ms: timings,
        result: "pass",
      }),
  );
} catch (error) {
  await cleanup();
  await cleanup(raceName);
  throw error;
}
