# Examples

Examples showing how to use the microsandbox SDK.

Some examples use git submodules for their sample Alpine assets.

```sh
git submodule update --init --recursive
```

## bind-root

Boots a sandbox from a local directory (bind-mounted rootfs), runs a few shell
commands, and stops it. Requires the `rootfs-alpine` submodule.

```sh
cargo run -p bind-root
```

## block-root

Demonstrates configuring a sandbox from the bundled `qcow2-alpine` disk image
submodule.

```sh
cargo run -p block-root
```

## net-ports

Publishes one TCP port and one UDP port from the guest to the host using the
top-level `SandboxBuilder::port()` and `port_udp()` helpers, then exercises
both mappings from the host.

```sh
cargo run -p net-ports
```

## named-volume

Creates a named volume, mounts it into two sandboxes (writer and reader),
and demonstrates persistence across sandbox lifecycles. Also shows the
host-side `VolumeFs` API and `VolumeHandle` metadata. Pulls `alpine:latest`
on first run.

```sh
cargo run -p named-volume
```

## oci-root

Pulls an OCI image (`alpine:latest`) from a registry and boots a sandbox from
it.

```sh
cargo run -p oci-root
```
