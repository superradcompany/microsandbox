import { Sandbox, Volume } from "microsandbox";

async function main() {
  // Create a named volume.
  const data = await Volume.create({ name: "my-data", quotaMib: 100 });

  // Sandbox A writes to the volume.
  const writer = await Sandbox.create({
    name: "writer",
    image: "alpine:latest",
    volumes: { "/data": { named: data.name } },
    replace: true,
  });

  await writer.shell("echo 'hello from sandbox A' > /data/message.txt");
  await writer.stopAndWait();

  // Sandbox B reads from the same volume.
  const reader = await Sandbox.create({
    name: "reader",
    image: "alpine:latest",
    volumes: { "/data": { named: data.name, readonly: true } },
    replace: true,
  });

  const output = await reader.shell("cat /data/message.txt");
  console.log(output.stdout());

  await reader.stopAndWait();

  // Clean up.
  await Sandbox.remove("writer");
  await Sandbox.remove("reader");
  await Volume.remove("my-data");
}

main();
