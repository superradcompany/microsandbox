# Examples

A collection of examples showing how to use the microsandbox SDK.

## Prerequisites

Before running any example, make sure you've done the following from the repo root:

1. **Build msb** (the sandbox runtime):

   ```sh
   just build
   ```

2. **Initialize the rootfs submodule** (provides the Alpine Linux root filesystem):

   ```sh
   git submodule update --init
   ```

That's it. You don't need `just build-deps` unless you've never built agentd and libkrunfw before — `just build` handles the rest.

## Running examples

All examples are run from the **repo root**. Point `MSB_PATH` to your freshly built `msb` binary:

```sh
MSB_PATH="$PWD/target/debug/msb" cargo run -p <example-name>
```

## Examples

| Example | Description |
|---------|-------------|
| [basic](basic/) | Boots a sandbox, runs a few shell commands, and stops it. A good starting point. |
