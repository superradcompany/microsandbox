// Compiled by npm run typecheck. Exercise the same fluent types consumers import.
import { Sandbox, Volume, type JobOutputSource, type VolumeKind } from "../../src/index.js";

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
  const job = await (await builder.create()).getJob("id");
  await job.logs({ sources: filters });
  // @ts-expect-error Replay gaps are events, not output sources.
  await job.logs({ sources: ["gap"] });
  return kind;
}
