<div align="center"><b>TypeScript SDK Examples</b></div>

<br />

> See the main [README](./README.md) for Rust examples and full documentation.

<br />

#### Run Code in a Sandbox

> ```typescript
> import { Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "my-sandbox",
>   image: "python",
>   cpus: 1,
>   memoryMib: 512,
> });
>
> const output = await sandbox.shell("print('Hello from a microVM!')");
> console.log(output.stdout());
>
> await sandbox.stopAndWait();
> ```
>
> Behind the scenes, `create()` pulls the image (if not cached), assembles the filesystem, boots a microVM. All in under a second.

#### Secrets That Never Enter the VM

> ```typescript
> import { Secret, Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "api-client",
>   image: "python",
>   secrets: [
>     Secret.env("OPENAI_API_KEY", { value: "sk-real-secret-123", allowHosts: ["api.openai.com"] }),
>   ],
> });
>
> // Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
> // Requests to api.openai.com: placeholder is replaced with the real key
> // Requests to any other host: placeholder stays, secret never leaks
> ```

#### Network Policy

> ```typescript
> import { Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "restricted",
>   image: "alpine",
>   network: {
>     policy: "public-only",            // blocks private/loopback
>     blockDomainSuffixes: [".evil.com"] // DNS-level blocking
>   },
> });
> ```
>
> Three built-in policies: `NetworkPolicy.publicOnly()` (default, blocks private IPs), `NetworkPolicy.allowAll()`, and `NetworkPolicy.none()` (fully airgapped).

#### Port Publishing

> ```typescript
> const sandbox = await Sandbox.create({
>   name: "web-server",
>   image: "alpine",
>   ports: { 8080: 80 }, // host:8080 → guest:80
> });
> ```

#### Named Volumes

> ```typescript
> import { Sandbox, Volume } from "microsandbox";
>
> // Create a volume with a quota.
> const data = await Volume.create({ name: "shared-data", quotaMib: 100 });
>
> // Sandbox A writes to it.
> const writer = await Sandbox.create({
>   name: "writer",
>   image: "alpine",
>   volumes: { "/data": { named: data.name } },
> });
>
> await writer.shell("echo 'hello' > /data/message.txt");
> await writer.stopAndWait();
>
> // Sandbox B reads from it.
> const reader = await Sandbox.create({
>   name: "reader",
>   image: "alpine",
>   volumes: { "/data": { named: data.name, readonly: true } },
> });
>
> const output = await reader.shell("cat /data/message.txt");
> console.log(output.stdout()); // hello
> ```

#### Scripts

> ```typescript
> const sandbox = await Sandbox.create({
>   name: "worker",
>   image: "ubuntu",
>   scripts: {
>     setup: "#!/bin/bash\napt-get update && apt-get install -y python3 curl",
>     start: "#!/bin/bash\nexec python3 /app/main.py",
>   },
> });
>
> await sandbox.shell("setup");
> const output = await sandbox.shell("start");
> ```

#### Patches

> ```typescript
> import { Patch, Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "configured",
>   image: "alpine",
>   patches: [
>     Patch.text("/etc/app.conf", "key=value\n"),
>     Patch.mkdir("/app", { mode: 0o755 }),
>     Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
>   ],
> });
> ```

#### Flexible Rootfs Sources

> ```typescript
> // OCI image (default)
> await Sandbox.create({ name: "oci", image: "python" });
>
> // Local directory
> await Sandbox.create({ name: "bind", image: "./my-rootfs" });
> ```

#### Guest Filesystem Access

> ```typescript
> // Write a file into the sandbox.
> await sandbox.fs().write("/tmp/input.txt", Buffer.from("some data"));
>
> // Read a file from the sandbox.
> const content = await sandbox.fs().readString("/tmp/output.txt");
>
> // List directory contents.
> const entries = await sandbox.fs().list("/tmp");
> ```

#### Streaming Execution

> ```typescript
> const handle = await sandbox.shellStream("python train.py");
>
> let event;
> while ((event = await handle.recv()) !== null) {
>   if (event.eventType === "stdout") process.stdout.write(event.data);
>   if (event.eventType === "stderr") process.stderr.write(event.data);
>   if (event.eventType === "exited") console.log(`Process exited: ${event.code}`);
> }
> ```
