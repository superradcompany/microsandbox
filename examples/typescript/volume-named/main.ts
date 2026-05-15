import { Sandbox, Volume } from "microsandbox";

const data = await Volume.builder("my-data").quota(100).create();

// Sandbox A writes to the volume.
{
  await using writer = await Sandbox.builder("writer")
    .image("alpine")
    .volume("/data", (m) => m.named(data.name))
    .replace()
    .create();
  await writer.shell("echo 'hello from sandbox A' > /data/message.txt");
}

// Sandbox B reads the same volume read-only.
{
  await using reader = await Sandbox.builder("reader")
    .image("alpine")
    .volume("/data", (m) => m.named(data.name).readonly())
    .replace()
    .create();
  console.log((await reader.shell("cat /data/message.txt")).stdout());
}

// Cleanup.
await Sandbox.remove("writer");
await Sandbox.remove("reader");
await Volume.remove("my-data");
