# TypeScript Examples

## Prerequisites

- Node.js >= 18
- `msb` + `libkrunfw` installed (auto-downloaded by the npm postinstall script)
- For `root-bind` and `root-block`: `git submodule update --init --recursive`

## Setup

Each example is a standalone Node.js project. Install dependencies first:

```sh
cd examples/typescript/<example>
npm install
```

## Running

```sh
npm start
```

For example:

```sh
cd examples/typescript/root-oci
npm install
npm start
```

## Examples

| Example | Description |
|---------|-------------|
| `root-oci` | OCI image rootfs |
| `root-bind` | Bind-mounted local directory |
| `root-block` | qcow2 disk image |
| `rootfs-patch` | Pre-boot filesystem patches |
| `volume-named` | Named volumes shared across sandboxes |
| `fs-read-stream` | Streaming file read |
| `metrics-stream` | Streaming resource metrics |
| `shell-attach` | Interactive shell attach |
| `net-basic` | Basic networking |
| `net-dns` | DNS filtering |
| `net-policy` | Network policies |
| `net-ports` | Port publishing |
| `net-secrets` | Secret injection |
| `net-tls` | TLS interception |
