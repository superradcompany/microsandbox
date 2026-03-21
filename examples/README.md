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

## oci-root

Pulls an OCI image (`alpine:latest`) from a registry and boots a sandbox from
it. No submodules needed — the image is fetched on first run.

```sh
cargo run -p oci-root
```
