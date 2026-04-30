import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("net-tls")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .network((n) => n.tls((t) => t.bypass("*.bypass-example.com")))
  .replace()
  .create();

const ca = await sandbox.shell(
  "ls /.msb/tls/ca.pem 2>&1 && echo FOUND || echo MISSING",
);
const caLines = ca.stdout().trim().split("\n");
console.log(`CA cert: ${caLines[caLines.length - 1]}`);

const sslEnv = await sandbox.shell("echo $SSL_CERT_FILE");
console.log(`SSL_CERT_FILE: ${sslEnv.stdout().trim()}`);

const certs = await sandbox.shell(
  "grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt",
);
console.log(`Certs in bundle: ${certs.stdout().trim()}`);

const http = await sandbox.shell(
  "wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL",
);
console.log(`\nHTTP: ${http.stdout().trim()}`);

const https = await sandbox.shell(
  "wget -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL",
);
console.log(`HTTPS (intercepted): ${https.stdout().trim()}`);

const noVerify = await sandbox.shell(
  "wget --no-check-certificate -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL",
);
console.log(`HTTPS (no-verify): ${noVerify.stdout().trim()}`);
