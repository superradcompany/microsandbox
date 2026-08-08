# Ruby SDK

The microsandbox Ruby SDK provides Ruby 3.1+ bindings for creating and
controlling local or cloud sandboxes.

## Installation

Install the gem:

```sh
gem install microsandbox
```

To use the local backend, install the microsandbox runtime and firmware once:

```ruby
require "microsandbox"

Microsandbox.install unless Microsandbox.installed?
```

Local sandboxes require Apple Silicon virtualization on macOS, KVM on Linux,
or WHP on Windows. Ruby CI currently covers Linux x86_64.

## Quick start

`Sandbox.with` stops the sandbox when the block exits, including when the block
raises an exception:

```ruby
require "microsandbox"

Microsandbox.install unless Microsandbox.installed?

Microsandbox::Sandbox.with(
  "my-sandbox",
  image: "python",
  cpus: 1,
  memory: 512
) do |sandbox|
  output = sandbox.exec("python", ["-c", "print('Hello from a microVM!')"])
  puts output.stdout
end
```

## Backends

The local backend is the default. Select a backend explicitly when needed:

```ruby
Microsandbox.use_local_backend! # Default
# Or:
Microsandbox.use_cloud_backend!(ENV.fetch("MSB_API_KEY"))
# Or:
Microsandbox.use_cloud_profile!("production")
```

## Lifecycle

A lifecycle-owning `Sandbox` stops when Ruby garbage-collects it. Prefer
`Sandbox.with` for scoped work. Call `sandbox.detach` when the VM must outlive
the Ruby object, then manage it through `Sandbox.get`.

If both a `Sandbox.with` block and its cleanup fail, the block's original
exception is preserved.

Blocking calls do not prevent other Ruby threads from running. Forked child
processes recreate the native runtime before use.

## Networking and secrets

`network: :none` disables networking. An allowlist creates a default-deny
egress policy:

```ruby
sandbox = Microsandbox::Sandbox.create(
  "secure-sandbox",
  image: "python",
  network: { allowed_hosts: ["api.example.com"], allowed_ports: [443] },
  secrets: [{
    env: "API_KEY",
    value: ENV.fetch("API_KEY"),
    allowed_host: "api.example.com"
  }]
)
```

The guest receives a placeholder for each secret. The host proxy substitutes
the real value only for the allowed TLS hostname. Secret values persist in
host-side sandbox configuration, so load them from a secret manager, never log
them, and rotate them after suspected host compromise.

## Supported surface

The gem supports sandbox lifecycle operations, collected exec and shell
output, SSH exec, logs, metrics, guest filesystem operations, local image,
volume, and snapshot management, and local or cloud backend selection.

Streaming exec, logs, metrics, and filesystem handles; interactive SSH/SFTP;
live modification plans; and the complete Rust network and mount builders are
not currently exposed. Use the Rust SDK when those APIs are required.

## Development

The native extension is built against the published `microsandbox` Rust crate
at the exact same version. `rake version_check` rejects non-exact requirements
and version drift between the gem, native extension, and Rust SDK.
