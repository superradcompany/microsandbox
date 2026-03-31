<div align="center"><b>Rust SDK Examples</b></div>

<br />

> See the main [README](./README.md) for TypeScript examples and full documentation.

<br />

#### Run Code in a Sandbox

> ```rs
> use microsandbox::Sandbox;
>
> #[tokio::main]
> async fn main() -> Result<(), Box<dyn std::error::Error>> {
>     let sandbox = Sandbox::builder("my-sandbox")
>         .image("python")
>         .cpus(1)
>         .memory(512)
>         .create()
>         .await?;
>
>     let output = sandbox.shell("print('Hello from a microVM!')").await?;
>     println!("{}", output.stdout()?);
>
>     sandbox.stop_and_wait().await?;
>     Ok(())
> }
> ```
>
> Behind the scenes, `create()` pulls the image (if not cached), assembles the filesystem, boots a microVM. All in under a second.

#### Secrets That Never Enter the VM

> ```rs
> let sandbox = Sandbox::builder("api-client")
>     .image("python")
>     .secret_env("OPENAI_API_KEY", "sk-real-secret-123", "api.openai.com")
>     .create()
>     .await?;
>
> // Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
> // Requests to api.openai.com: placeholder is replaced with the real key
> // Requests to any other host: placeholder stays, secret never leaks
> ```

#### Network Policy

> ```rs
> use microsandbox::{NetworkPolicy, Sandbox};
>
> let sandbox = Sandbox::builder("restricted")
>     .image("alpine")
>     .network(|n| {
>         n.policy(NetworkPolicy::public_only())  // blocks private/loopback
>          .block_domain_suffix(".evil.com")       // DNS-level blocking
>     })
>     .create()
>     .await?;
> ```
>
> Three built-in policies: `NetworkPolicy::public_only()` (default, blocks private IPs), `NetworkPolicy::allow_all()`, and `NetworkPolicy::none()` (fully airgapped).

#### Port Publishing

> ```rs
> let sandbox = Sandbox::builder("web-server")
>     .image("alpine")
>     .port(8080, 80)  // host:8080 → guest:80
>     .create()
>     .await?;
> ```

#### Named Volumes

> ```rs
> use microsandbox::{Sandbox, Volume, size::SizeExt};
>
> // Create a volume with a quota.
> let data = Volume::builder("shared-data").quota(100.mib()).create().await?;
>
> // Sandbox A writes to it.
> let writer = Sandbox::builder("writer")
>     .image("alpine")
>     .volume("/data", |v| v.named(data.name()))
>     .create()
>     .await?;
>
> writer.shell("echo 'hello' > /data/message.txt").await?;
> writer.stop_and_wait().await?;
>
> // Sandbox B reads from it.
> let reader = Sandbox::builder("reader")
>     .image("alpine")
>     .volume("/data", |v| v.named(data.name()).readonly())
>     .create()
>     .await?;
>
> let output = reader.shell("cat /data/message.txt").await?;
> println!("{}", output.stdout()?); // hello
> ```

#### Scripts

> ```rs
> let sandbox = Sandbox::builder("worker")
>     .image("ubuntu")
>     .script("setup", "#!/bin/bash\napt-get update && apt-get install -y python3 curl")
>     .script("start", "#!/bin/bash\nexec python3 /app/main.py")
>     .create()
>     .await?;
>
> sandbox.shell("setup").await?;
> let output = sandbox.shell("start").await?;
> ```

#### Patches

> ```rs
> let sandbox = Sandbox::builder("configured")
>     .image("alpine")
>     .patch(|p| {
>         p.text("/etc/app.conf", "key=value\n", None, false)
>          .mkdir("/app", Some(0o755))
>          .append("/etc/hosts", "127.0.0.1 myapp.local\n")
>     })
>     .create()
>     .await?;
> ```

#### Flexible Rootfs Sources

> ```rs
> // OCI image (default)
> Sandbox::builder("oci").image("python:3.12")
>
> // Local directory
> Sandbox::builder("bind").image("./my-rootfs")
>
> // QCOW2 disk image
> use microsandbox::sandbox::ImageBuilder;
> Sandbox::builder("block").image(|img: ImageBuilder| img.disk("./disk.qcow2").fstype("ext4"))
> ```

#### Guest Filesystem Access

> ```rs
> // Write a file into the sandbox.
> sandbox.fs().write("/tmp/input.txt", b"some data").await?;
>
> // Read a file from the sandbox.
> let content = sandbox.fs().read_to_string("/tmp/output.txt").await?;
>
> // List directory contents.
> let entries = sandbox.fs().list("/tmp").await?;
> ```

#### Streaming Execution

> ```rs
> use microsandbox::ExecEvent;
>
> let mut handle = sandbox.shell_stream("python train.py").await?;
>
> while let Some(event) = handle.recv().await {
>     match event {
>         ExecEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
>         ExecEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
>         ExecEvent::Exited { code } => println!("Process exited: {code}"),
>         _ => {}
>     }
> }
> ```
