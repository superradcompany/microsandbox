// Compiled by npm run typecheck. Exercise the same fluent types consumers import.
import { Sandbox, Volume, type JobOutputSource, type LogLevel, type PullPolicy, type VolumeKind } from "../../src/index.js";

export async function publicTypes(filters: JobOutputSource[]) {
  const volume = await Volume.get("cache");
  const kind: VolumeKind = (await volume.info()).kind;
  const builder = Sandbox.builder("task")
    .imageWith(image => image.oci("alpine"))
    .pullPolicy("if-missing")
    .logLevel("info")
    .registry(registry => registry.caCertsPath("ca.pem"))
    .network(network => network.maxTcpConnections(64));
  // @ts-expect-error Unsupported policies must be caught before creation.
  builder.pullPolicy("if-mising");
  // @ts-expect-error The callback receives a network builder.
  builder.network(network => network.nonexistentMethod());
  const sandbox = await builder.create();
  await sandbox.exec("echo", new Set(["hello"]));
  await sandbox.attach("echo", ["hello"] as const);
  // @ts-expect-error A string is a single argument, not an argv list.
  await sandbox.execStream("echo", "hello");
  const config = await sandbox.config();
  const level: LogLevel | null = config.spec.runtime.logLevel;
  if (level) builder.logLevel(level);
  if (config.kind === "local") {
    const policy: PullPolicy = config.spec.pullPolicy;
    builder.pullPolicy(policy);
  }
  const job = await sandbox.getJob("id");
  await job.logs({ sources: filters });
  // @ts-expect-error Replay gaps are events, not output sources.
  await job.logs({ sources: ["gap"] });
  return kind;
}
