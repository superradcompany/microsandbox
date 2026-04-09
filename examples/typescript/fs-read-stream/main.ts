import { Sandbox } from "microsandbox";

async function main() {
  console.log("Creating sandbox (image=alpine)");

  const sandbox = await Sandbox.create({
    name: "fs-read-stream",
    image: "alpine",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  // Create a file with some content inside the sandbox.
  await sandbox.shell("dd if=/dev/urandom of=/tmp/data.bin bs=1M count=10");

  // Stream the file back in chunks using for-await-of.
  const stream = await sandbox.fs().readStream("/tmp/data.bin");
  let totalBytes = 0;
  let chunkCount = 0;

  for await (const chunk of stream) {
    chunkCount++;
    totalBytes += chunk.length;
    console.log(`Chunk ${chunkCount}: ${chunk.length} bytes`);
  }

  const expectedBytes = 10 * 1024 * 1024;
  if (totalBytes === expectedBytes) {
    console.log("File size matches expected value");
  } else {
    throw new Error(`expected ${expectedBytes} bytes, got ${totalBytes}`);
  }

  // Stop the sandbox gracefully.
  await sandbox.stopAndWait();

  console.log("Sandbox stopped.");
}

main();
