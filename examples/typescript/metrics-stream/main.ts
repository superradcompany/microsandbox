import { Sandbox } from "microsandbox";

async function main() {
  console.log("Creating sandbox (image=alpine)");

  const sandbox = await Sandbox.create({
    name: "metrics-stream",
    image: "alpine",
    cpus: 1,
    memoryMib: 512,
    replace: true,
  });

  // Generate some CPU load in the background.
  await sandbox.shell("dd if=/dev/urandom of=/dev/null bs=1M count=100 &");

  // Stream metrics every second, print 5 samples.
  let count = 0;
  for await (const m of await sandbox.metricsStream(1000)) {
    console.log(
      `[${count}] CPU: ${m.cpuPercent.toFixed(1)}%, Mem: ${Math.floor(m.memoryBytes / 1024 / 1024)} MB, Disk R/W: ${m.diskReadBytes}/${m.diskWriteBytes} bytes`
    );
    count++;
    if (count >= 5) break;
  }

  console.log(`Collected ${count} metric samples`);

  await sandbox.stopAndWait();
  console.log("Sandbox stopped.");
}

main();
