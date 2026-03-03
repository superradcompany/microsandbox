# libkrunfw Build Plan

## Overview

libkrunfw bundles the Linux kernel as a native shared library (`.so` on Linux, `.dylib` on macOS) that is loaded at runtime via `dlopen`. It is a runtime dependency of `msb_krun`, not a Rust crate dependency.

This plan covers:

1. Vendoring libkrunfw as a git submodule
2. Building the library from source via a justfile
3. Optional prebuilt binary download via a `build.rs` feature flag

### Why Vendor libkrunfw?

- **Self-contained SDK** — users shouldn't need to system-install libkrunfw
- **Version pinning** — prevents ABI mismatches between msb_krun and the kernel library
- **Custom patches** — upstream libkrunfw carries patches we depend on (clean PID 1 exit, vsock dgram, Apple TSO); forking gives us control
- **Reproducible builds** — build from a pinned commit, not whatever's in `/usr/local/lib`

---

## 1. Git Submodule Setup

### Fork

Fork `containers/libkrunfw` to `zerocore-ai/libkrunfw`. This gives us:

- Release tagging for prebuilt binaries (e.g., `v4.10.0`)
- Ability to carry custom patches if upstream diverges
- Mirrors the `zerocore-ai/libkrun` pattern

### Submodule

```bash
cd microsandbox
git submodule add https://github.com/zerocore-ai/libkrunfw.git lib/libkrunfw
git submodule update --init
```

#### Repository Structure

```
microsandbox/
├── lib/
│   └── libkrunfw/              # Git submodule (zerocore-ai/libkrunfw)
│       ├── Makefile
│       ├── bin2cbundle.py
│       ├── build_on_krunvm.sh  # (unused — replaced by justfile Docker build)
│       ├── config-libkrunfw_aarch64
│       ├── config-libkrunfw_x86_64
│       ├── patches/
│       └── ...
├── microsandbox/
│   ├── Cargo.toml
│   ├── build.rs                # NEW: optional prebuilt download
│   ├── bin/
│   └── lib/
├── justfile                    # NEW: build recipes
└── Cargo.toml
```

---

## 2. Build Process

### How libkrunfw is Built

The build has two stages:

1. **Compile the Linux kernel** — requires a Linux environment (can't build Linux kernel on macOS natively)
2. **Generate the shared library** — convert kernel binary to C source via `bin2cbundle.py`, then compile to `.so`/`.dylib`

#### Stage 1: Kernel Compilation

1. Download kernel tarball (`linux-6.12.34` from `cdn.kernel.org`)
2. Apply patches from `patches/` (21 patches: vsock dgram, TSO, TSI, etc.)
3. Copy arch-specific kernel config (`config-libkrunfw_{arch}`)
4. Run `make olddefconfig && make`
5. Output: `vmlinux` (x86_64) or `Image` (aarch64)

#### Stage 2: Shared Library

1. Run `bin2cbundle.py` to convert kernel binary → `kernel.c` (C array with page-aligned kernel bytes + accessor functions)
2. Compile: `cc -fPIC -DABI_VERSION=4 -shared -o libkrunfw.{so,dylib} kernel.c`
3. Strip (Linux only)

### Platform-Specific Build

#### Linux (Native)

Both stages run natively. Straightforward.

Dependencies: `gcc`, `make`, `python3`, `python3-pyelftools`, `bc`, `flex`, `bison`, `libelf-dev`, `libssl-dev`, `dwarves`, `curl`

#### macOS (Docker)

Stage 1 runs inside a Docker container (Fedora-based, matching upstream's builder choice). Stage 2 runs on the macOS host.

Flow:

```
┌─────────────────────────────────────────────────────┐
│  Docker (Fedora)                                    │
│  1. Install kernel build deps (dnf builddep kernel) │
│  2. Download + patch + compile kernel               │
│  3. Run bin2cbundle.py → kernel.c                   │
│  (bind-mounted lib/libkrunfw/ ↔ /work)              │
└─────────────────────────────────────────────────────┘
                        │
                   kernel.c (on host via bind mount)
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│  macOS Host                                         │
│  cc -fPIC -shared -o libkrunfw.4.dylib kernel.c     │
└─────────────────────────────────────────────────────┘
```

This replaces the existing `build_on_krunvm.sh` with Docker. The plan is to eventually replace Docker with microsandbox itself (dogfooding).

---

## 3. Justfile

The justfile lives at the microsandbox project root.

### Recipes

```just
# ── libkrunfw ─────────────────────────────────────────────────────────────────

# Build libkrunfw for the current platform
build-libkrunfw:
    #!/usr/bin/env bash
    set -euo pipefail
    OS="$(uname -s)"
    if [ "$OS" = "Linux" ]; then
        just _build-libkrunfw-linux
    elif [ "$OS" = "Darwin" ]; then
        just _build-libkrunfw-macos
    else
        echo "Unsupported OS: $OS"
        exit 1
    fi

# Clean libkrunfw build artifacts
clean-libkrunfw:
    cd lib/libkrunfw && make clean

# ── Internal recipes ──────────────────────────────────────────────────────────

# Linux: build kernel + shared library natively
_build-libkrunfw-linux:
    cd lib/libkrunfw && make -j"$(nproc)"

# macOS: build kernel in Docker, compile dylib on host
_build-libkrunfw-macos:
    #!/usr/bin/env bash
    set -euo pipefail

    LIBKRUNFW_DIR="$(pwd)/lib/libkrunfw"
    ARCH="$(uname -m)"

    # Stage 1: Compile kernel inside Docker (Fedora)
    docker run --rm \
        -v "$LIBKRUNFW_DIR:/work" \
        -w /work \
        fedora:latest \
        bash -c "
            dnf install -y 'dnf-command(builddep)' python3-pyelftools curl && \
            dnf builddep -y kernel && \
            make -j\$(nproc)
        "

    # Stage 2: Compile dylib on macOS host
    # kernel.c was generated inside Docker via bind mount
    ABI_VERSION=4
    cc -fPIC -DABI_VERSION=$ABI_VERSION -shared \
        -o "$LIBKRUNFW_DIR/libkrunfw.$ABI_VERSION.dylib" \
        "$LIBKRUNFW_DIR/kernel.c"

    echo "Built: lib/libkrunfw/libkrunfw.$ABI_VERSION.dylib"

# Install libkrunfw to a target directory (for use by msb_krun at runtime)
install-libkrunfw target_dir="target/lib":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{ target_dir }}"
    OS="$(uname -s)"
    ABI_VERSION=4
    if [ "$OS" = "Linux" ]; then
        FULL_VERSION="4.10.0"
        cp "lib/libkrunfw/libkrunfw.so.$FULL_VERSION" "{{ target_dir }}/"
        cd "{{ target_dir }}"
        ln -sf "libkrunfw.so.$FULL_VERSION" "libkrunfw.so.$ABI_VERSION"
        ln -sf "libkrunfw.so.$ABI_VERSION" "libkrunfw.so"
    elif [ "$OS" = "Darwin" ]; then
        cp "lib/libkrunfw/libkrunfw.$ABI_VERSION.dylib" "{{ target_dir }}/"
        cd "{{ target_dir }}"
        ln -sf "libkrunfw.$ABI_VERSION.dylib" "libkrunfw.dylib"
    fi
    echo "Installed libkrunfw to {{ target_dir }}/"
```

### Key Design Decisions

1. **Fedora base image** — matches upstream's builder convention; `dnf builddep kernel` pulls all kernel build deps in one command
2. **Single Docker run** — no persistent container; `--rm` ensures clean state
3. **Bind mount** — `lib/libkrunfw/` is mounted at `/work` so `kernel.c` appears on host after the Docker run
4. **ABI_VERSION variable** — currently `4`, centralized for easy bumping
5. **install recipe** — copies the built library to a location where msb_krun can find it at runtime (e.g., `target/lib/`), with proper symlinks

---

## 4. Prebuilt Download (Feature Flag)

### Feature Flag

The `microsandbox` crate gets a `prebuilt-libkrunfw` feature flag. When enabled, `build.rs` downloads the prebuilt library from `zerocore-ai/libkrunfw` GitHub releases.

```toml
# microsandbox/Cargo.toml
[features]
prebuilt-libkrunfw = []

[build-dependencies]
reqwest = { version = "0.13", features = ["blocking"], optional = true }

[features]
prebuilt-libkrunfw = ["dep:reqwest"]
```

### build.rs

```rust
fn main() {
    #[cfg(feature = "prebuilt-libkrunfw")]
    download_libkrunfw();
}

#[cfg(feature = "prebuilt-libkrunfw")]
fn download_libkrunfw() {
    use std::path::PathBuf;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let lib_dir = out_dir.join("lib");
    std::fs::create_dir_all(&lib_dir).unwrap();

    let version = "4.10.0";
    let abi_version = "4";

    let (filename, url) = if cfg!(target_os = "macos") {
        let name = format!("libkrunfw.{abi_version}.dylib");
        let url = format!(
            "https://github.com/zerocore-ai/libkrunfw/releases/download/v{version}/{name}"
        );
        (name, url)
    } else {
        let name = format!("libkrunfw.so.{version}");
        let url = format!(
            "https://github.com/zerocore-ai/libkrunfw/releases/download/v{version}/{name}"
        );
        (name, url)
    };

    let dest = lib_dir.join(&filename);

    if !dest.exists() {
        let bytes = reqwest::blocking::get(&url)
            .unwrap_or_else(|e| panic!("Failed to download libkrunfw from {url}: {e}"))
            .bytes()
            .unwrap();
        std::fs::write(&dest, &bytes).unwrap();
    }

    // Tell downstream code where to find the library
    println!("cargo:rustc-env=LIBKRUNFW_PATH={}", dest.display());
    println!("cargo:rerun-if-changed=build.rs");
}
```

### How msb_krun Finds libkrunfw

The `KernelBuilder::krunfw_path()` API in msb_krun allows specifying an explicit path:

```rust
// When prebuilt-libkrunfw is enabled, use the downloaded path
let krunfw_path = env!("LIBKRUNFW_PATH");

VmBuilder::new()
    .kernel(|k| k.krunfw_path(krunfw_path))
    // ...
```

When the feature is NOT enabled, the user is expected to either:
- Build via `just build-libkrunfw && just install-libkrunfw`
- Have libkrunfw installed system-wide (fallback to OS dynamic linker search)

---

## 5. GitHub Releases (zerocore-ai/libkrunfw)

### Release Artifacts

Each release (e.g., `v4.10.0`) publishes:

| Artifact | Platform | Architecture |
|----------|----------|-------------|
| `libkrunfw.4.dylib` | macOS | aarch64 (Apple Silicon) |
| `libkrunfw.so.4.10.0` | Linux | x86_64 |
| `libkrunfw.so.4.10.0` | Linux | aarch64 |

### Release Process

1. Build on each target platform (CI or manual)
2. Tag the fork: `git tag v4.10.0 && git push --tags`
3. Create GitHub release with the built artifacts
4. Update `ABI_VERSION`/`FULL_VERSION` in the justfile and `build.rs` when bumping

### Versioning

- **ABI version** (`4`) — bumped when the `krunfw_get_kernel()` / `krunfw_get_version()` interface changes (rare)
- **Full version** (`4.10.0`) — bumped when kernel version, patches, or config changes
- msb_krun checks `krunfw_get_version()` at runtime to verify ABI compatibility

---

## 6. Developer Workflow

### First-Time Setup

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/zerocore-ai/microsandbox.git

# Or if already cloned
git submodule update --init

# Build libkrunfw
just build-libkrunfw
just install-libkrunfw

# Build microsandbox
cargo build
```

### Quick Start (Prebuilt)

```bash
# Skip building libkrunfw from source
cargo build --features prebuilt-libkrunfw
```

### Updating libkrunfw

```bash
cd lib/libkrunfw
git fetch origin
git checkout v4.11.0  # or whatever new version
cd ../..
git add lib/libkrunfw
git commit -S -m "chore: update libkrunfw to v4.11.0"
just build-libkrunfw
```

---

## Summary

| Component | Approach |
|-----------|----------|
| **Source** | Git submodule at `lib/libkrunfw/` (fork: `zerocore-ai/libkrunfw`) |
| **Linux build** | Native via justfile (`make -j$(nproc)`) |
| **macOS build** | Docker (Fedora) for kernel + native `cc` for dylib |
| **Prebuilt download** | `prebuilt-libkrunfw` feature flag, `build.rs` downloads from GitHub releases |
| **Runtime loading** | `msb_krun` loads via `dlopen`; path set via `KernelBuilder::krunfw_path()` |
| **Future** | Replace Docker with microsandbox for macOS builds (dogfooding) |
