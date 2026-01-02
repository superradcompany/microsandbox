use std::str::FromStr;

use crate::{
    oci::{
        DOCKER_REFERENCE_TYPE_ANNOTATION, Reference, global_cache::GlobalCacheOps,
        mocks::mock_registry_and_db,
    },
    utils,
};

use futures::StreamExt;
use oci_client::manifest::OciManifest;
use oci_spec::image::{Digest, DigestAlgorithm, Os};
use sqlx::Row;
use tokio::{fs, io::AsyncWriteExt, test};

#[test]
#[ignore = "makes network requests to Docker registry to pull an image"]
async fn test_docker_pull_image() -> anyhow::Result<()> {
    let (registry, db, _dir) = mock_registry_and_db().await;
    let reference = Reference::from_str("alpine:latest").unwrap();
    let result = registry.pull_image(&reference).await;
    assert!(result.is_ok(), "{:?}", result.err());

    // Verify image record in database
    let image = sqlx::query("SELECT * FROM images WHERE reference = ?")
        .bind(reference.as_db_key())
        .fetch_one(&db)
        .await?;
    assert!(image.get::<i64, _>("size_bytes") > 0);

    // Verify manifest record
    let manifest = sqlx::query("SELECT * FROM manifests WHERE image_id = ?")
        .bind(image.get::<i64, _>("id"))
        .fetch_one(&db)
        .await?;
    assert_eq!(manifest.get::<i64, _>("schema_version"), 2);

    // Verify config record
    let manifest_id = manifest.get::<i64, _>("id");
    let config = sqlx::query("SELECT * FROM configs WHERE manifest_id = ?")
        .bind(manifest_id)
        .fetch_one(&db)
        .await?;
    assert!(matches!(config.get::<String, _>("os"), s if s == Os::Linux.to_string()));

    // Verify layers were downloaded and match records
    let layers = sqlx::query(
        "SELECT * FROM manifest_layers
        INNER JOIN layers ON manifest_layers.layer_id = layers.id
        WHERE manifest_id = ?",
    )
    .bind(manifest_id)
    .fetch_all(&db)
    .await?;
    assert!(!layers.is_empty());

    for layer in layers {
        let digest = layer.get::<String, _>("digest");
        let size = layer.get::<i64, _>("size_bytes");
        let layer_path = registry
            .global_cache()
            .tar_download_dir()
            .join(&digest)
            .with_extension("tar");

        // Verify layer file exists and has correct size
        assert!(layer_path.exists(), "Layer file {} not found", digest);
        assert_eq!(
            fs::metadata(&layer_path).await?.len() as i64,
            size,
            "Layer {} size mismatch",
            digest
        );

        // Verify layer hash
        let parts: Vec<&str> = digest.split(':').collect();
        let algorithm = &DigestAlgorithm::try_from(parts[0])?;
        let expected_hash = parts[1];
        let actual_hash = hex::encode(utils::get_file_hash(&layer_path, algorithm).await?);
        assert_eq!(actual_hash, expected_hash, "Layer {} hash mismatch", digest);
    }

    Ok(())
}

#[test]
#[ignore = "makes network requests to Docker registry to fetch image index"]
async fn test_docker_fetch_index() -> anyhow::Result<()> {
    let (registry, _, _) = mock_registry_and_db().await;
    let reference = Reference::from_str("alpine:latest").unwrap();

    let result = registry.fetch_index(&reference).await;
    let OciManifest::ImageIndex(index) = result.unwrap() else {
        panic!("alpine image should be image index");
    };

    // Verify manifest entries have required fields
    for manifest in index.manifests {
        assert!(manifest.size > 0);
        assert!(manifest.digest.to_string().starts_with("sha256:"));
        assert!(manifest.media_type.to_string().contains("manifest"));

        // Verify platform info for non-attestation manifests
        if !manifest
            .annotations
            .as_ref()
            .is_some_and(|a| a.contains_key(DOCKER_REFERENCE_TYPE_ANNOTATION))
        {
            let platform = manifest.platform.as_ref().expect("Platform info missing");
            assert_eq!(platform.os, oci_spec::image::Os::Linux);
        }
    }

    Ok(())
}

#[test]
#[ignore = "makes network requests to Docker registry to fetch image manifest"]
async fn test_docker_fetch_manifest_and_config() -> anyhow::Result<()> {
    let (registry, _, _) = mock_registry_and_db().await;
    let reference = Reference::from_str("alpine:latest").unwrap();
    let (manifest, config) = registry
        .fetch_manifest_and_config(&reference)
        .await
        .unwrap();

    // Verify manifest has required fields
    assert_eq!(manifest.schema_version, 2);
    assert!(manifest.config.size > 0);
    assert!(manifest.config.digest.to_string().starts_with("sha256:"));
    assert!(manifest.config.media_type.to_string().contains("config"));

    // Verify manifest layers
    assert!(!manifest.layers.is_empty());
    for layer in manifest.layers {
        assert!(layer.size > 0);
        assert!(layer.digest.to_string().starts_with("sha256:"));
        assert!(layer.media_type.to_string().contains("layer"));
    }

    // Verify config fields
    assert_eq!(config.os, oci_client::config::Os::Linux);
    assert!(config.rootfs.r#type == "layers");
    assert!(!config.rootfs.diff_ids.is_empty());

    // Verify config fields: optional but common fields
    if let Some(created) = config.created {
        assert!(created.timestamp_millis() > 0);
    }
    if let Some(config_fields) = config.config {
        if let Some(env) = config_fields.env {
            assert!(!env.is_empty());
        }
        if let Some(cmd) = config_fields.cmd {
            assert!(!cmd.is_empty());
        }
    }

    Ok(())
}

#[test]
#[ignore = "makes network requests to Docker registry to fetch image blob"]
async fn test_docker_fetch_image_blob() -> anyhow::Result<()> {
    let (registry, _, _) = mock_registry_and_db().await;
    let reference = Reference::from_str("alpine:latest").unwrap();

    // Get a layer digest from manifest
    let (manifest, _) = registry.fetch_manifest_and_config(&reference).await?;
    let layer = manifest.layers.first().unwrap();
    let digest = Digest::try_from(layer.digest.clone()).unwrap();
    let mut stream = registry
        .fetch_digest_blob(&reference, &digest, 0, None)
        .await?;

    // Download the blob to a temporary file
    let temp_download_dir = tempfile::tempdir()?;
    let temp_file = temp_download_dir.path().join("test_blob");
    let mut file = fs::File::create(&temp_file).await?;
    let mut total_size = 0;

    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        total_size += bytes.len();
        file.write_all(&bytes).await?;
    }

    // Verify size matches
    assert!(total_size > 0);
    assert_eq!(total_size as i64, layer.size);

    // Verify hash matches
    assert_eq!(digest.to_string(), layer.digest);

    Ok(())
}
