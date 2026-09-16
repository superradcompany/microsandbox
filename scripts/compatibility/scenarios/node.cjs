#!/usr/bin/env node
// Use the installed SDK's v0.7.0 public contract from an isolated consumer directory.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");

const reportPath = process.env.MSB_COMPAT_REPORT;
const report = { language: "node", status: "running", cases: [], cleanup_errors: [] };
const marker = "compat-node-persistent";
const networkMarker = "compat-node-network-control";
let current;

function saveReport() {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function checkpoint(name, details = {}) {
  current.checks.push({ name, ...details });
  saveReport();
}

function startCase(name) {
  current = { name, status: "running", checks: [] };
  report.cases.push(current);
  saveReport();
}

function within(file, root) {
  const relative = path.relative(root, file);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function packageOwner(file) {
  for (let directory = path.dirname(file); ; directory = path.dirname(directory)) {
    const manifest = path.join(directory, "package.json");
    if (fs.existsSync(manifest)) return { path: manifest, ...JSON.parse(fs.readFileSync(manifest)) };
    assert.notEqual(path.dirname(directory), directory, `no package owns ${file}`);
  }
}

async function installedSdk() {
  // Resolve from the consumer work directory even when this script lives in the checkout.
  const consumerRequire = createRequire(path.join(process.cwd(), "compat-consumer.cjs"));
  const entry = fs.realpathSync(consumerRequire.resolve("microsandbox"));
  const root = fs.realpathSync(process.env.MSB_COMPAT_SDK_ROOT);
  const expected = process.env.MSB_COMPAT_SDK_VERSION;
  assert.ok(within(entry, root), "SDK import escaped the isolated installation");
  assert.ok(!process.env.NAPI_RS_NATIVE_LIBRARY_PATH, "native library override must be unset");
  const sdk = await import(pathToFileURL(entry).href);
  const loaded = Object.keys(require.cache).filter((file) => file.endsWith(".node"));
  assert.equal(loaded.length, 1, "expected exactly one loaded native SDK extension");
  const nativePath = fs.realpathSync(loaded[0]);
  const packageMetadata = packageOwner(entry);
  const nativeMetadata = packageOwner(nativePath);
  const digest = crypto.createHash("sha256").update(fs.readFileSync(nativePath)).digest("hex");
  report.sdk = {
    root, package_path: entry, package_version: packageMetadata.version,
    native_path: nativePath, native_package: nativeMetadata.name,
    native_package_version: nativeMetadata.version, native_sha256: digest,
    node: process.execPath,
  };
  saveReport();
  assert.ok(within(nativePath, root), "native import escaped the isolated installation");
  assert.equal(packageMetadata.name, "microsandbox");
  assert.equal(packageMetadata.version, expected, "SDK package version mismatch");
  assert.equal(nativeMetadata.version, expected, "native package version mismatch");
  assert.ok(nativeMetadata.name === "microsandbox" ||
    nativeMetadata.name.startsWith("@superradcompany/microsandbox-"),
  "loaded extension does not belong to a microsandbox package");
  if (process.env.MSB_COMPAT_NATIVE_SHA256) {
    assert.equal(digest, process.env.MSB_COMPAT_NATIVE_SHA256, "native artifact SHA256 mismatch");
  }
  checkpoint("installed-sdk-identity", report.sdk);
  return sdk;
}

function processJson(executable, args) {
  return JSON.parse(execFileSync(executable, args, {
    encoding: "utf8", timeout: 45_000, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function verifyRuntime(name) {
  // The helper examines /proc rather than trusting package metadata or launch arguments.
  const result = processJson(process.env.MSB_COMPAT_PYTHON || "python3", [
    process.env.MSB_COMPAT_VERIFY_RUNTIME, name,
  ]);
  checkpoint("live-runtime-identity", { sandbox: name, result });
}

async function output(sandbox, command, args, code = 0) {
  const result = await sandbox.exec(command, args);
  assert.equal(result.code, code, `${command} ${JSON.stringify(args)}: ${result.stderr()}`);
  assert.equal(result.success, code === 0, "exec success disagrees with exit code");
  return result.stdout();
}

async function networkProbe(sandbox, port) {
  // A literal gateway address avoids depending on DNS, which deny-all also blocks.
  const script = "gateway=$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf); " +
    `test -n "$gateway" || exit 72; exec wget -T 3 -q -O - "http://$gateway:${port}/"`;
  return sandbox.exec("sh", ["-c", script]);
}

function validateConfig(config, name, mounts, denied) {
  assert.equal(config.name, name, "persisted sandbox name changed");
  assert.equal(config.resources.memory_mib, 256, "memory configuration was lost");
  assert.equal(config.resources.cpus, 1, "CPU configuration was lost");
  assert.deepEqual(config.image.Oci.root_disk, { kind: "managed", size_mib: 128 });
  assert.equal(Object.fromEntries(config.env.map(({ key, value }) => [key, value])).MSB_COMPAT_MARKER,
    marker, "environment configuration was lost");
  assert.equal(config.mounts.length, mounts.length, "mount count changed");
  assert.deepEqual(config.mounts.map((mount) => mount.guest).sort(), [...mounts].sort());
  assert.ok(config.mounts.every((mount) => mount.type === "Tmpfs" && mount.size_mib === 8));
  assert.equal(config.network.enabled, true, "network interface unexpectedly disabled");
  if (denied) {
    assert.deepEqual(config.network.policy, {
      default_egress: "deny", default_ingress: "deny", rules: [],
    }, "deny-all policy changed");
  } else {
    // An omitted policy is the serialized default-public profile in v0.7.0.
    assert.equal(config.network.policy ?? null, null, "default networking acquired an explicit policy");
  }
}

async function suite() {
  assert.equal(process.env.MSB_COMPAT_CASE || "all", "all", "unknown scenario selection");
  startCase("installed-sdk-identity");
  const sdk = await installedSdk();
  current.status = "passed";
  const owned = new Set();
  const prefix = `compat-node-${crypto.randomUUID().slice(0, 10)}`;
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "Content-Length": Buffer.byteLength(networkMarker) });
    response.end(networkMarker);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;

  async function remove(name) {
    await sdk.Sandbox.remove(name);
    await assert.rejects(() => sdk.Sandbox.get(name), sdk.SandboxNotFoundError);
    owned.delete(name);
    checkpoint("remove", { sandbox: name });
  }

  function builder(name) {
    return sdk.Sandbox.builder(name).image(process.env.MSB_COMPAT_IMAGE)
      .rootDisk(128).memory(256).cpus(1).maxDuration(300);
  }

  try {
    startCase("network-positive-control");
    const controlName = `${prefix}-control`;
    owned.add(controlName);
    const control = await builder(controlName)
      .network((network) => network.policy(sdk.NetworkPolicy.allowAll())).create();
    verifyRuntime(controlName);
    const firstProbe = await networkProbe(control, port);
    assert.ok(firstProbe.success && firstProbe.stdout() === networkMarker,
      `allow-all network control failed: ${firstProbe.stderr()}`);
    checkpoint("host-http-reachable", { sandbox: controlName });
    current.status = "passed";

    const cases = [
      { label: "default-zero-mounts", count: 0, denied: false },
      { label: "deny-all-one-mount", count: 1, denied: true },
      { label: "default-multiple-mounts", count: 2, denied: false },
    ];
    for (const [index, { label, count, denied }] of cases.entries()) {
      startCase(label);
      const name = `${prefix}-${index}`;
      const mounts = Array.from({ length: count }, (_, number) => `/compat-tmpfs-${number}`);
      owned.add(name);
      let options = builder(name).env("MSB_COMPAT_MARKER", marker);
      if (denied) options = options.network((network) => network.policy(sdk.NetworkPolicy.none()));
      for (const mount of mounts) options = options.volume(mount, (volume) => volume.tmpfs().size(8));
      let sandbox = await options.create();
      verifyRuntime(name);
      const handle = await sdk.Sandbox.get(name);
      const config = JSON.parse(handle.configJson);
      validateConfig(config, name, mounts, denied);
      assert.equal(handle.status, "running");
      const cli = processJson(process.env.MSB_COMPAT_CLI, ["inspect", name, "--format", "json"]);
      assert.equal(cli.name, name);
      assert.equal(cli.status.toLowerCase(), "running");
      validateConfig(cli.config, name, mounts, denied);
      checkpoint("create-and-shared-cli-catalog", { sandbox: name, id: handle.id, config });

      assert.equal(await output(sandbox, "sh", ["-c", "printf exec-ok; exit 7"], 7), "exec-ok");
      assert.equal(await output(sandbox, "sh", ["-c", 'printf %s "$MSB_COMPAT_MARKER"']), marker);
      await output(sandbox, "sh", ["-ec", `printf %s ${marker} > /compat-marker`]);
      for (const mount of mounts) {
        assert.equal((await output(sandbox, "stat", ["-f", "-c", "%T", mount])).trim(), "tmpfs");
        await output(sandbox, "sh", ["-ec", `printf scratch > ${mount}/marker`]);
      }
      checkpoint("exec-environment-and-mounts", { tmpfs_mounts: mounts });

      const probe = await networkProbe(sandbox, port);
      assert.ok(probe.code === 1 && !probe.stdout(), "network policy allowed restricted host HTTP");
      const controlProbe = await networkProbe(control, port);
      assert.ok(controlProbe.success && controlProbe.stdout() === networkMarker,
        "network control stopped responding during the negative probe");
      checkpoint(denied ? "network-deny-all" : "network-default-host-denied", {
        exit_code: probe.code, stderr: probe.stderr(),
      });

      await sandbox.stop();
      assert.equal((await sdk.Sandbox.get(name)).status, "stopped", "stop did not persist");
      checkpoint("stop", { sandbox: name });
      if (index === 0) {
        const archivePath = path.join(process.cwd(), `${prefix}.tar`);
        const archive = await sdk.Snapshot.builder(`${prefix}-disk`).fromSandbox(name)
          .createArchive(archivePath, true);
        assert.ok(fs.statSync(archivePath).size > 0, "disk archive was not written");
        const restoredName = `${prefix}-restored`;
        owned.add(restoredName);
        const restored = await sdk.Sandbox.restore(archivePath).name(restoredName)
          .maxDuration(300).restore();
        verifyRuntime(restoredName);
        assert.equal(await output(restored, "cat", ["/compat-marker"]), marker,
          "disk archive restore lost the persistent marker");
        checkpoint("disk-snapshot-archive-restore", {
          archive: archive.path, sandbox: restoredName, bytes: fs.statSync(archivePath).size,
        });
        await restored.stop();
        await remove(restoredName);
      }

      sandbox = await sdk.Sandbox.start(name);
      verifyRuntime(name);
      assert.equal(await output(sandbox, "cat", ["/compat-marker"]), marker,
        "stop/start lost the persistent root marker");
      assert.equal(await output(sandbox, "sh", ["-c", 'printf %s "$MSB_COMPAT_MARKER"']), marker,
        "stop/start lost the environment");
      for (const mount of mounts) await output(sandbox, "test", ["!", "-e", `${mount}/marker`]);
      checkpoint("restart-persistence", { sandbox: name, tmpfs_reset: true });
      await sandbox.stop();
      await remove(name);
      current.status = "passed";
      saveReport();
    }
    await control.stop();
    await remove(controlName);
  } finally {
    // Cleanup is restricted to our unique fixtures; cleanup failures remain visible in the report.
    for (const name of owned) {
      try {
        const handle = await sdk.Sandbox.get(name);
        await handle.destroy({ force: true });
      } catch (error) {
        if (!(error instanceof sdk.SandboxNotFoundError)) {
          report.cleanup_errors.push({ sandbox: name, error: String(error) });
        }
      }
    }
    await new Promise((resolve) => server.close(resolve));
    saveReport();
  }
  assert.equal(report.cleanup_errors.length, 0, "fixture cleanup failed");
}

saveReport();
suite().then(() => {
  report.status = "passed";
}).catch((error) => {
  report.status = "failed";
  report.failure = { type: error.name, message: error.message, stack: error.stack };
  if (current) current.status = "failed";
  console.error(error);
  process.exitCode = 1;
}).finally(saveReport);
