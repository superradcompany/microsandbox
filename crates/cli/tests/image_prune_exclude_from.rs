//! End-to-end CLI tests for `msb image prune --exclude-from`.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use microsandbox::{Image, LocalContext};
use microsandbox_image::{CachedImageMetadata, CachedLayerMetadata, GlobalCache, ImageConfig};

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn test_metadata(id: char, layers: &[char]) -> CachedImageMetadata {
    CachedImageMetadata {
        manifest_digest: format!("sha256:{}", id.to_string().repeat(64)),
        config_digest: format!("sha256:{}", id.to_string().repeat(64)),
        raw_manifest_json: "{}".into(),
        raw_config_json: "{}".into(),
        config: ImageConfig::default(),
        layers: layers
            .iter()
            .map(|layer| CachedLayerMetadata {
                digest: format!("sha256:{}", layer.to_string().repeat(64)),
                media_type: None,
                size_bytes: Some(7),
                diff_id: format!("sha256:{}", layer.to_string().repeat(64)),
            })
            .collect(),
    }
}

async fn install_image(
    home: &Path,
    reference: &str,
    metadata: &CachedImageMetadata,
) -> GlobalCache {
    let local = LocalContext::builder()
        .config_path(home.join("config.json"))
        .home(home)
        .build()
        .unwrap();
    let cache = GlobalCache::new(&local.cache_dir()).unwrap();
    for path in cache.metadata_paths(metadata).unwrap() {
        std::fs::write(path, b"payload").unwrap();
    }
    cache
        .write_image_metadata_async(&reference.parse().unwrap(), metadata)
        .await
        .unwrap();
    Image::persist(&local, reference, metadata.clone())
        .await
        .unwrap();
    cache
}

async fn cached_references(home: &Path) -> HashSet<String> {
    let local = LocalContext::builder()
        .config_path(home.join("config.json"))
        .home(home)
        .build()
        .unwrap();
    Image::list_local(&local)
        .await
        .unwrap()
        .into_iter()
        .map(|handle| handle.reference().to_string())
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn image_prune_exclude_from_missing_fails_closed_without_deleting() {
    let home = tempfile::tempdir().unwrap();
    let alpine_meta = test_metadata('a', &['1']);
    let cache = install_image(home.path(), "docker.io/library/alpine:3.20", &alpine_meta).await;
    let missing = home.path().join("does-not-exist.txt");

    let output = Command::new(env!("CARGO_BIN_EXE_msb"))
        .env("MSB_HOME", home.path())
        .args(["image", "prune", "--yes", "--exclude-from"])
        .arg(&missing)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "expected missing --exclude-from file to fail, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exclude-from"),
        "expected clear exclude-from error, got: {stderr}"
    );
    assert!(
        cached_references(home.path())
            .await
            .contains("docker.io/library/alpine:3.20")
    );
    assert!(
        cache
            .image_metadata_path(&"docker.io/library/alpine:3.20".parse().unwrap())
            .exists()
    );
    assert!(
        cache
            .layer_erofs_path(&alpine_meta.layers[0].diff_id.parse().unwrap())
            .exists()
    );
}

#[tokio::test]
async fn image_prune_exclude_from_preserves_pinned_and_prunes_unpinned() {
    let home = tempfile::tempdir().unwrap();
    // Shared base layer '0', plus unique layers '1', '2', '3'.
    let alpine_meta = test_metadata('a', &['0', '1']);
    let python_meta = test_metadata('b', &['0', '2']);
    let ubuntu_meta = test_metadata('c', &['0', '3']);

    let cache = install_image(home.path(), "docker.io/library/alpine:3.20", &alpine_meta).await;
    install_image(
        home.path(),
        "docker.io/library/python:3.12-slim",
        &python_meta,
    )
    .await;
    install_image(home.path(), "docker.io/library/ubuntu:24.04", &ubuntu_meta).await;

    let exclude_file_1 = home.path().join("exclude-1.txt");
    std::fs::write(
        &exclude_file_1,
        "# Pre-warmed base images\n\n  alpine:3.20  \n   # indented comment\n",
    )
    .unwrap();

    let exclude_file_2 = home.path().join("exclude-2.txt");
    std::fs::write(&exclude_file_2, "\tpython:3.12-slim\r\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_msb"))
        .env("MSB_HOME", home.path())
        .args([
            "image",
            "prune",
            "--yes",
            "--format",
            "json",
            "--exclude-from",
        ])
        .arg(&exclude_file_1)
        .arg("--exclude-from")
        .arg(&exclude_file_2)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "prune failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["image_refs_removed"], 1);
    assert_eq!(report["manifests_removed"], 1);
    assert_eq!(report["layers_removed"], 1);

    let remaining = cached_references(home.path()).await;
    assert_eq!(
        remaining,
        HashSet::from([
            "docker.io/library/alpine:3.20".to_string(),
            "docker.io/library/python:3.12-slim".to_string(),
        ])
    );

    // Pinned images, shared layer, and pinned unique layers remain on disk.
    assert!(
        cache
            .image_metadata_path(&"alpine:3.20".parse().unwrap())
            .exists()
    );
    assert!(
        cache
            .image_metadata_path(&"python:3.12-slim".parse().unwrap())
            .exists()
    );
    assert!(
        cache
            .layer_erofs_path(&alpine_meta.layers[0].diff_id.parse().unwrap())
            .exists()
    );
    assert!(
        cache
            .layer_erofs_path(&alpine_meta.layers[1].diff_id.parse().unwrap())
            .exists()
    );
    assert!(
        cache
            .layer_erofs_path(&python_meta.layers[1].diff_id.parse().unwrap())
            .exists()
    );

    // Unpinned image metadata and its unique layer are removed.
    assert!(
        !cache
            .image_metadata_path(&"ubuntu:24.04".parse().unwrap())
            .exists()
    );
    assert!(
        !cache
            .layer_erofs_path(&ubuntu_meta.layers[1].diff_id.parse().unwrap())
            .exists()
    );
}
