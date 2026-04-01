import { Sandbox } from "microsandbox";

async function main() {
  const sandbox = await Sandbox.create({
    name: "net-tls",
    image: "alpine",
    cpus: 1,
    memoryMib: 512,
    network: {
      tls: { bypass: ["*.bypass-example.com"] },
    },
    replace: true,
  });

  // Verify CA cert was placed and installed.
  const ca = await sandbox.shell("ls /.msb/tls/ca.pem 2>&1 && echo FOUND || echo MISSING");
  const caLines = ca.stdout().trim().split("\n");
  console.log(`CA cert: ${caLines[caLines.length - 1]}`);

  // Check SSL env vars set by agentd.
  const sslEnv = await sandbox.shell("echo $SSL_CERT_FILE");
  console.log(`SSL_CERT_FILE: ${sslEnv.stdout().trim()}`);

  // Count certs in bundle (system + ours).
  const certs = await sandbox.shell("grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt");
  console.log(`Certs in bundle: ${certs.stdout().trim()}`);

  // HTTP (non-TLS) still works normally.
  const http = await sandbox.shell("wget -q -O /dev/null --timeout=5 http://example.com && echo OK || echo FAIL");
  console.log(`\nHTTP: ${http.stdout().trim()}`);

  // HTTPS through the TLS interception proxy.
  const https = await sandbox.shell("wget -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL");
  console.log(`HTTPS (intercepted): ${https.stdout().trim()}`);

  // HTTPS with --no-check-certificate to test TCP proxy path.
  const noVerify = await sandbox.shell("wget --no-check-certificate -q -O /dev/null --timeout=10 https://example.com 2>&1 && echo OK || echo FAIL");
  console.log(`HTTPS (no-verify): ${noVerify.stdout().trim()}`);

  await sandbox.stopAndWait();
  await Sandbox.remove("net-tls");
}

main();
