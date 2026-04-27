import { Sandbox } from "microsandbox";

console.log("Creating sandbox (image=alpine)");

await using sandbox = await Sandbox.builder("fs-read-stream")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

await sandbox.shell("dd if=/dev/urandom of=/tmp/data.bin bs=1M count=10");

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
