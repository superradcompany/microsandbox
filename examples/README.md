# Examples

Examples showing how to use the microsandbox SDK.

Some examples use git submodules for their sample Alpine assets.

```sh
git submodule update --init --recursive
```

## block-root

Demonstrates configuring a sandbox from the bundled `qcow2-alpine` disk image
submodule.

```sh
cargo run -p block-root
```

## simple-root

Boots a sandbox, runs a few shell commands, and stops it. A good starting point.

```sh
cargo run -p simple-root
```
