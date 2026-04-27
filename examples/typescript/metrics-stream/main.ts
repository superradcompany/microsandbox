import { Sandbox } from "microsandbox";

console.log("Creating sandbox (image=alpine)");

await using sandbox = await Sandbox.builder("metrics-stream")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .replace()
  .create();

await sandbox.shell("dd if=/dev/urandom of=/dev/null bs=1M count=100 &");

let count = 0;
for await (const m of await sandbox.metricsStream(1000)) {
  console.log(
    `[${count}] CPU: ${m.cpuPercent.toFixed(1)}%, Mem: ${Math.floor(
      m.memoryBytes / 1024 / 1024,
    )} MB, Disk R/W: ${m.diskReadBytes}/${m.diskWriteBytes} bytes`,
  );
  count++;
  if (count >= 5) break;
}

console.log(`Collected ${count} metric samples`);
