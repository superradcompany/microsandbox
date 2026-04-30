import { Sandbox } from "microsandbox";

console.log("Creating sandbox with published port 8080 → 80");

await using sandbox = await Sandbox.builder("net-ports")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .port(8080, 80)
  .replace()
  .create();

const start = await sandbox.shell(
  `(while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 24\\r\\nConnection: close\\r\\n\\r\\nHello from microsandbox!' | nc -l -p 80; done) >/tmp/net-ports.log 2>&1 & echo ok`,
);
console.log(`HTTP server started: ${start.stdout().trim()}`);

try {
  const resp = await fetch("http://127.0.0.1:8080/index.html", {
    signal: AbortSignal.timeout(5000),
  });
  console.log(`Host-side: ${(await resp.text()).trim()}`);
} catch (e) {
  console.error(`Host-side: could not reach guest server: ${e}`);
}
