# Ruby SDK

The microsandbox Ruby SDK provides Ruby 3.1+ bindings for creating and
controlling local or cloud sandboxes.

## Installation

Install the gem:

```sh
gem install microsandbox
```

> [!NOTE]
> Platform gems are currently built and validated in CI but not yet published
> to RubyGems — every `gem install microsandbox` still compiles the source gem
> and needs a Rust toolchain. This section describes the state once the release
> wiring ships them.

Precompiled platform gems carry the native extension, so these combinations
install without a Rust toolchain:

| Gem platform        | Ruby     | Notes              |
| ------------------- | -------- | ------------------ |
| `x86_64-linux-gnu`  | 3.1–4.0  | glibc 2.35+        |
| `aarch64-linux-gnu` | 3.1–4.0  | glibc 2.35+        |
| `arm64-darwin`      | 3.1–4.0  | Apple Silicon      |
| `x64-mingw-ucrt`    | 3.1–4.0  | RubyInstaller 3.1+ |

The Linux gems require glibc 2.35 or newer (Ubuntu 22.04, Debian 12, and
later). The platform name carries no glibc version, so on an older glibc host
the platform gem still installs but fails to load — force the source gem there
(see below).

The Linux gems need `libcap-ng0` at runtime. Debian and Ubuntu ship it in the
base system — the stock `ruby:slim` images load the gem with no extra
packages, which CI verifies — so this only matters on stripped-down
environments such as distroless images.

Installing a platform gem requires RubyGems 3.3.11 or newer; earlier releases
mismatch `-linux` gems against glibc hosts. Run `gem update --system` first if
`gem --version` reports anything older.

musl (Alpine), Windows on ARM, and any other platform or Ruby version fall
back to the source gem automatically. The source gem compiles the extension
during install and therefore needs a Rust toolchain (1.85 or newer).

To compile from source even where a platform gem exists:

```sh
gem install microsandbox --platform ruby
```

With Bundler:

```ruby
gem "microsandbox", force_ruby_platform: true
```

To build a platform gem from a checkout, install every target Ruby, then run
from `sdk/ruby`:

```sh
rake version_check cargo:patch_workspace
rake gem:stage # Once per installed Ruby, 3.1 through 4.0
GEM_PLATFORM=arm64-darwin rake gem:platform
```

`gem:platform` refuses to package unless all five ABIs are staged. Set
`RUBY_ABIS` (for example `RUBY_ABIS=3.4`) to relax that when testing against a
single local Ruby; CI never sets it.

`cargo:patch_workspace` points the build at the in-tree Rust SDK and drops
`ext/microsandbox/Cargo.lock`, which pins the published crate graph and cannot
resolve against the patched path. When you are done, run
`rake cargo:unpatch_workspace` — it removes the gitignored patch config (which
would otherwise keep later local builds silently resolving against the in-tree
SDK) and restores the lockfile.

To use the local backend, install the microsandbox runtime and firmware once:

```ruby
require "microsandbox"

Microsandbox.install unless Microsandbox.installed?
```

Local sandboxes require Apple Silicon virtualization on macOS or KVM on Linux. On Windows, use Windows 11 on x64 or ARM64 and enable WHP. Ruby CI currently covers Linux x86_64.

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

SSH exec inherits the global inactivity timeout by default. Override it for a
single command in seconds, or use `0` to disable it:

```ruby
output = sandbox.ssh_exec("long-running-agent", inactivity_timeout: 1_800)
persistent = sandbox.ssh_exec("long-running-agent", inactivity_timeout: 0)
```

Streaming exec, logs, metrics, and filesystem handles; interactive SSH/SFTP;
live modification plans; and the complete Rust network and mount builders are
not currently exposed. Use the Rust SDK when those APIs are required.

## Development

The native extension is built against the published `microsandbox` Rust crate
at the exact same version. `rake version_check` rejects non-exact requirements
and version drift between the gem, native extension, and Rust SDK.
