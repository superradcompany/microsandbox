# microsandbox-image

Pull OCI container images, extract their layers, and cache everything locally. This crate handles the full image lifecycle for [microsandbox](https://github.com/zerocore-ai/microsandbox) — from resolving a multi-platform manifest to producing ready-to-mount layer directories.

- **Multi-platform resolution** — automatically picks the right manifest for your OS and architecture
- **Parallel downloads** — all layers download and extract concurrently with SHA256 verification
- **Content-addressable caching** — duplicate layers across images are stored once, with cross-process safety via `flock()`
- **Progress streaming** — real-time events for download, extraction, and indexing stages
- **Sidecar indexes** — builds binary indexes per layer for fast OverlayFs lookups at runtime

## Quick Start

```rust
use microsandbox_image::{GlobalCache, Platform, PullOptions, Registry};

let cache = GlobalCache::new("/path/to/cache")?;
let platform = Platform::host_linux();
let registry = Registry::new(platform, cache)?;

let reference = "docker.io/library/alpine:latest".parse()?;
let result = registry.pull(&reference, &PullOptions::default()).await?;

// Extracted layer directories, bottom-to-top
for layer_path in &result.layers {
    println!("{}", layer_path.display());
}

// Parsed image config (env, cmd, entrypoint, user, etc.)
println!("entrypoint: {:?}", result.config.entrypoint);
println!("env: {:?}", result.config.env);
```

## Authentication

```rust
use microsandbox_image::RegistryAuth;

// Public registries — no credentials needed
let registry = Registry::new(platform, cache)?;

// Private registries
let auth = RegistryAuth::Basic {
    username: "user".into(),
    password: "token".into(),
};
let registry = Registry::with_auth(platform, cache, auth)?;
```

## Pull Policies

Control when the crate contacts the registry vs. uses the local cache.

```rust
use microsandbox_image::{PullOptions, PullPolicy};

// Use cache if available, download otherwise (default)
let opts = PullOptions { pull_policy: PullPolicy::IfMissing, ..Default::default() };

// Always fetch a fresh manifest, but reuse cached layers by digest
let opts = PullOptions { pull_policy: PullPolicy::Always, ..Default::default() };

// Cache-only — error if the image isn't already cached
let opts = PullOptions { pull_policy: PullPolicy::Never, ..Default::default() };
```

## Progress Reporting

Stream progress events while the download runs in the background.

```rust
let (mut progress, task) = registry.pull_with_progress(&reference, &PullOptions::default());

tokio::spawn(async move {
    while let Some(event) = progress.recv().await {
        match event {
            PullProgress::Resolved { layer_count, .. } => {
                println!("Pulling {layer_count} layers");
            }
            PullProgress::LayerDownloadProgress { downloaded_bytes, total_bytes, .. } => {
                println!("Downloaded {downloaded_bytes}/{total_bytes:?} bytes");
            }
            PullProgress::Complete { .. } => {
                println!("Done!");
            }
            _ => {}
        }
    }
});

let result = task.await??;
```

## Multi-Platform Images

Fat manifests (OCI Image Index) are automatically resolved to your target platform. `Platform::host_linux()` detects the current architecture by default.

```rust
use microsandbox_image::Platform;

// Auto-detect (e.g. linux/amd64 or linux/arm64)
let platform = Platform::host_linux();

// Explicit platform
let platform = Platform::new("linux", "arm64");

// With variant (e.g. armv7)
let platform = Platform::with_variant("linux", "arm", "v7");
```
