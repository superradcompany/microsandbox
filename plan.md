# Proposal: Parallel Layer Processing Pipeline

## Problem

The current pull pipeline processes layers in three strictly sequential phases:

```
1. Download ALL layers ──(barrier)──→ 2. Extract+Index each layer one-by-one ──→ 3. Return
```

This means:
- Extraction of layer 0 waits for ALL downloads (including a 500MB layer 4)
- Each layer's extraction blocks the next, even though most layers are self-contained
- Each layer's indexing blocks the next extraction, even though indexing only reads
- Total wall time = max(all downloads) + sum(all extractions) + sum(all indexes)

## Current Code Structure

### Orchestration (`registry.rs:215-267`)

```rust
// Step 5: Download all layers concurrently (barrier at end)
let download_futures = layer_descriptors.iter().enumerate().map(|(i, desc)| {
    async move { layer.download(...).await }
});
futures::future::try_join_all(download_futures).await?;   // ← BARRIER

// Step 6: Extract layers one-by-one, sequentially
let mut extracted_dirs: Vec<PathBuf> = Vec::new();
for (i, desc) in layer_descriptors.iter().enumerate() {
    layer.extract(&extracted_dirs, ...).await?;            // ← SEQUENTIAL
    layer.build_index().await?;                            // ← BLOCKS NEXT
    extracted_dirs.push(layer.extracted_dir());
}
```

### Extraction (`extraction.rs:73-287`)

`extract_layer()` takes `parent_layers: &[PathBuf]` — a list of already-extracted lower layer directories. This is used by `ensure_parent_dir()` (line 338) when a tar entry references a path whose parent directory doesn't exist in the current layer. In that case, it:

1. Creates the missing directory via `create_dir_all`
2. Searches `parent_layers` (bottom-to-top) for the same directory
3. Copies the `override_stat` xattr from the parent layer's version of that directory

This creates a **data dependency**: layer N's extraction needs layers 0..N-1 fully extracted.

### Why This Dependency Matters

Our OverlayFs implementation searches layers **top-down and stops at the first match** for any path lookup (`inode.rs:591-632`). When `getattr` is called on a directory, the metadata comes from the **topmost layer that contains it**, read via the on-disk `override_stat` xattr.

This means if layer 2 implicitly creates `usr/local/` with a default/wrong xattr, and layer 0 has `usr/local/` with the correct xattr, the guest sees layer 2's wrong metadata — layer 0 is never consulted.

**However**: in the vast majority of OCI images, every layer's tar includes explicit directory entries for all paths it touches. The `ensure_parent_dir` fallback to parent layers is a **rare edge case** — it handles the degenerate scenario where a tar contains `usr/local/bin/python` without a preceding `usr/local/` directory entry.

## Proposed Solution: Parallel Extract + Post-Fixup

Extract all layers in parallel with no parent layer dependencies. Then run a fast sequential fixup pass to correct any implicitly-created directories.

### Architecture

```
Phase 1: FULLY PARALLEL (download → extract → index, per layer)
┌─ download[0] → extract[0] → index[0] ─┐
│  download[1] → extract[1] → index[1]  │ all concurrent
│  download[2] → extract[2] → index[2]  │
└─ download[3] → extract[3] → index[3] ─┘
                      │
                 join_all
                      │
Phase 2: FAST SEQUENTIAL FIXUP (xattr correction, rare)
for layer in 1..N (bottom-to-top):
    for each implicitly-created dir (tracked during phase 1):
        copy correct xattr from the lowest layer that defines it
```

### Wall Time Comparison (5-layer image)

Assumptions: download=2s/layer, extraction=1s/layer, indexing=0.3s/layer

| Approach | Wall Time | Speedup |
|----------|-----------|---------|
| Current (all sequential) | 2.0 + 5.0 + 1.5 = **8.5s** | — |
| Parallel extract + fixup | max(2+1+0.3) + ~0 = **3.3s** | **61%** |

## Detailed Design

### Step 1: Modify `extract_layer` to Track Implicit Directories

Currently `ensure_parent_dir` creates missing directories and copies xattrs inline. Change it to:

1. **Remove the `parent_layers` parameter** from `extract_layer()`
2. **`ensure_parent_dir` still creates missing directories** with a default xattr (`uid=0, gid=0, mode=S_IFDIR|0o755, rdev=0`)
3. **Track which directories were implicitly created** (not from a tar directory entry) by accumulating their relative paths into a `Vec<PathBuf>` returned alongside the extraction result

**Changes to `extraction.rs`:**

```rust
/// Result of layer extraction, including directories that need post-fixup.
pub(crate) struct ExtractionResult {
    /// Relative paths of directories created implicitly (not from tar entries).
    /// These need xattr fixup from lower layers in a post-processing pass.
    pub implicit_dirs: Vec<PathBuf>,
}

pub(crate) async fn extract_layer(
    tar_path: &Path,
    dest: &Path,
    media_type: Option<&str>,
    // parent_layers parameter REMOVED
) -> ImageResult<ExtractionResult> {
    let mut implicit_dirs: Vec<PathBuf> = Vec::new();
    // ...
    // Pass implicit_dirs to ensure_parent_dir:
    ensure_parent_dir(&full_path, dest, &mut implicit_dirs)?;
    // ...
    Ok(ExtractionResult { implicit_dirs })
}
```

**Changes to `ensure_parent_dir`:**

```rust
fn ensure_parent_dir(
    path: &Path,
    dest: &Path,
    implicit_dirs: &mut Vec<PathBuf>,  // replaces parent_layers
) -> ImageResult<()> {
    // ... (same walk-up-missing-ancestors logic) ...

    for dir in missing.into_iter().rev() {
        std::fs::create_dir_all(&dir)?;
        set_host_permissions(&dir, 0o700)?;

        // Default xattr — may be corrected in fixup pass.
        let mode = S_IFDIR | 0o755;
        set_override_stat(&dir, 0, 0, mode, 0)?;

        // Track for post-fixup.
        if let Ok(rel) = dir.strip_prefix(dest) {
            implicit_dirs.push(rel.to_path_buf());
        }
    }
    Ok(())
}
```

### Step 2: Add Fixup Function

New function in `extraction.rs` (or `layer/mod.rs`):

```rust
/// Fix xattrs on implicitly-created directories by copying from lower layers.
///
/// After parallel extraction, directories that were created implicitly
/// (not from tar entries) may have default xattrs. This pass searches
/// lower layers bottom-to-top and copies the correct xattr.
pub(crate) fn fixup_implicit_dirs(
    layer_dir: &Path,
    implicit_dirs: &[PathBuf],
    lower_layers: &[PathBuf],  // layers below this one, bottom-to-top
) -> ImageResult<()> {
    for rel_dir in implicit_dirs {
        let target = layer_dir.join(rel_dir);
        if !target.exists() {
            continue;
        }

        // Search lower layers top-to-bottom (most recent first) for this dir.
        for lower in lower_layers.iter().rev() {
            let source = lower.join(rel_dir);
            if source.exists() {
                if let Ok(Some(data)) = xattr::get(&source, OVERRIDE_XATTR_KEY) {
                    let _ = xattr::set(&target, OVERRIDE_XATTR_KEY, &data);
                }
                break;
            }
        }
    }
    Ok(())
}
```

### Step 3: Restructure `pull_inner` Orchestration

Replace the current sequential download-barrier→extract loop with fully parallel pipelines:

```rust
// Step 5+6: Download, extract, and index ALL layers in parallel.
let layer_futures: Vec<_> = layer_descriptors
    .iter()
    .enumerate()
    .map(|(i, layer_desc)| {
        let layer = Layer::new(layer_desc.digest.clone(), &self.cache);
        let client = self.client.clone();
        let oci_ref = oci_ref.clone();
        let progress = progress.clone();
        let media_type = layer_desc.media_type.clone();
        let diff_id = diff_ids.get(i).cloned().unwrap_or_default();
        let build_index = options.build_index;
        let force = options.force;
        let size = layer_desc.size;

        async move {
            // Download
            layer.download(&client, &oci_ref, size, force, progress.as_ref(), i).await?;

            // Extract (no parent_layers — parallel safe)
            let result = layer.extract(progress.as_ref(), i, media_type.as_deref(), &diff_id).await?;

            // Index
            if build_index {
                if let Some(ref p) = progress {
                    p.send(PullProgress::LayerIndexStarted { layer_index: i });
                }
                layer.build_index().await?;
                if let Some(ref p) = progress {
                    p.send(PullProgress::LayerIndexComplete { layer_index: i });
                }
            }

            Ok::<_, ImageError>((i, layer.extracted_dir(), result.implicit_dirs))
        }
    })
    .collect();

let results = futures::future::try_join_all(layer_futures).await?;

// Collect results in layer order.
let mut layer_results: Vec<(PathBuf, Vec<PathBuf>)> = vec![(PathBuf::new(), Vec::new()); layer_count];
for (i, extracted_dir, implicit_dirs) in results {
    layer_results[i] = (extracted_dir, implicit_dirs);
}

// Step 6b: Sequential fixup pass (fast — only implicit dirs).
let extracted_dirs: Vec<PathBuf> = layer_results.iter().map(|(dir, _)| dir.clone()).collect();
for i in 1..layer_count {
    let (ref layer_dir, ref implicit_dirs) = layer_results[i];
    if !implicit_dirs.is_empty() {
        extraction::fixup_implicit_dirs(layer_dir, implicit_dirs, &extracted_dirs[..i])?;
    }
}
```

### Step 4: Update `Layer::extract` Signature

Remove `parent_extracted_dirs` parameter, return `ExtractionResult`:

```rust
// Before:
pub async fn extract(
    &self,
    parent_extracted_dirs: &[PathBuf],
    progress: Option<&PullProgressSender>,
    layer_index: usize,
    media_type: Option<&str>,
    diff_id: &str,
) -> ImageResult<()>

// After:
pub async fn extract(
    &self,
    progress: Option<&PullProgressSender>,
    layer_index: usize,
    media_type: Option<&str>,
    diff_id: &str,
) -> ImageResult<ExtractionResult>
```

### Step 5: Re-indexing After Fixup

**Not needed.** The sidecar index records `d_type` (file type) from `entry_rec.mode >> 12`, which is `S_IFDIR >> 12 = 4` (`DT_DIR`) regardless of permission bits. The fixup only changes permission bits and uid/gid in the xattr — the index's `d_type` field remains correct.

The OverlayFs never reads uid/gid/mode from the index for `getattr` — it always reads the real on-disk xattr. So re-indexing would be wasted work.

### Why This Is Safe

| Concern | Analysis |
|---------|----------|
| **Directory metadata correctness** | Fixup pass copies correct xattr from lower layers after all layers are extracted. Same data as current sequential approach. |
| **Rare edge case** | Most OCI layers include explicit directory entries. `implicit_dirs` will typically be empty. Fixup pass is a no-op. |
| **Index correctness** | Index only uses `d_type` (file type bits), not permission bits. `S_IFDIR` is always correct for directories. No re-index needed. |
| **Cross-process safety** | Per-layer `flock()` still prevents two processes from extracting the same digest concurrently. Parallel extraction is within a single process across different digests. |
| **Whiteout handling** | Whiteouts are per-layer markers. Each layer's whiteouts are extracted independently — no cross-layer dependency during extraction. OverlayFs interprets them at runtime. |
| **Hardlink handling** | Hardlinks are resolved within the same layer (pass 2 of extraction). No cross-layer dependency. |

### Error Handling

If any layer's download/extract/index fails, `try_join_all` propagates the first error. Already-extracted layers remain in cache (valid, with `.complete` marker). The fixup pass is skipped on error.

## Files to Modify

| File | Change |
|------|--------|
| `crates/image/lib/layer/extraction.rs` | Add `ExtractionResult` type. Remove `parent_layers` from `extract_layer`. Change `ensure_parent_dir` to track implicit dirs. Add `fixup_implicit_dirs`. |
| `crates/image/lib/layer/mod.rs` | Update `Layer::extract` signature (remove `parent_extracted_dirs`, return `ExtractionResult`). |
| `crates/image/lib/registry.rs` | Rewrite `pull_inner` steps 5-6: parallel `try_join_all` for download+extract+index, then sequential fixup. |

## Verification

1. `cargo test` — all existing tests pass
2. Add unit test for `fixup_implicit_dirs` with a multi-layer temp directory setup
3. Add test that extracts a layer with a missing parent dir and verifies the default xattr is set
4. Add test that fixup correctly copies xattr from a lower layer
5. Manual test: `docker pull python:3.12` equivalent — verify guest sees correct directory permissions
