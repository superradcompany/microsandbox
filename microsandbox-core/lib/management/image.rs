//! Container image management for Microsandbox.
//!
//! This module provides functionality for managing container images from various
//! registries. It supports pulling images from Docker and Sandboxes.io registries,
//! handling image layers, and managing the local image cache.

use crate::{
    MicrosandboxResult,
    management::db::{self},
    oci::{GlobalCache, LayerDependencies, LayerOps, Reference, Registry},
};
use futures::future;
#[cfg(feature = "cli")]
use microsandbox_utils::term::{self};
use microsandbox_utils::{LAYERS_SUBDIR, OCI_DB_FILENAME, env};
use oci_spec::image::{Digest, Os, Platform};
use std::{path::PathBuf, sync::Arc};
use tempfile::tempdir;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "cli")]
/// Spinner message used for extracting layers.
const EXTRACT_LAYERS_MSG: &str = "Extracting layers";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Pulls an image using whatever registry is configured.
///
/// ## Arguments
///
/// * `image` - The reference to the image to pull
/// * `layer_output_dir` - The path to store the layer files
///
/// # Examples
///
/// ```no_run
/// use microsandbox_core::management::image;
/// use microsandbox_core::oci::Reference;
/// use std::path::PathBuf;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let layer_output_dir = Some(PathBuf::from("/custom/path"));
///
///     // Pull a single image from Docker registry
///     image::pull("docker.io/library/ubuntu:latest".parse().unwrap(), layer_output_dir.clone()).await?;
///
///     // Pull an image from the default registry (when no registry is specified in the reference)
///     image::pull("nginx:latest".parse().unwrap(), layer_output_dir.clone()).await?;
///
///     // You can set the OCI_REGISTRY_DOMAIN environment variable to specify your default registry
///     unsafe { std::env::set_var("OCI_REGISTRY_DOMAIN", "docker.io"); }
///     image::pull("alpine:latest".parse().unwrap(), layer_output_dir.clone()).await?;
///
///     // Pull an image from Docker registry and store the layers in a custom directory
///     image::pull("docker.io/library/ubuntu:latest".parse().unwrap(), layer_output_dir).await?;
///
///     Ok(())
/// }
/// ```
pub async fn pull(
    image: Reference,
    layer_extraction_dir: Option<PathBuf>,
) -> MicrosandboxResult<()> {
    let temp_download_dir = tempdir()?.into_path();
    tracing::info!(?temp_download_dir, "temporary download directory");

    let microsandbox_home_path = env::get_microsandbox_home_path();
    let db_path = microsandbox_home_path.join(OCI_DB_FILENAME);
    let db = db::get_or_create_pool(&db_path, &db::OCI_DB_MIGRATOR).await?;
    let layer_output_dir = layer_extraction_dir
        .unwrap_or_else(|| env::get_microsandbox_home_path().join(LAYERS_SUBDIR));
    let layer_cache = GlobalCache::new(temp_download_dir, layer_output_dir, db.clone()).await?;

    // libkrun is based solely on Linux, so explicitly set the platform to Linux
    let mut platform = Platform::default();
    platform.set_os(Os::Linux);

    Registry::new(db.clone(), platform, layer_cache)
        .await?
        .pull_image(&image)
        .await
}

/// A bundle of layers that are related (e.g., parent layers for a given layer)
#[derive(Clone)]
pub struct ContainerImage {
    layers: Vec<Arc<dyn LayerOps>>,
}

impl ContainerImage {
    /// Creates a new image bundle.
    ///
    /// ## Arguments
    ///
    /// * `layers` - A vector of layers that are related (e.g., parent layers for a given layer)
    ///
    /// ## Returns
    ///
    /// * `Self` - The image bundle
    pub(crate) fn new(layers: Vec<Arc<dyn LayerOps>>) -> Self {
        Self { layers }
    }

    /// Returns a slice of the layers.
    pub(crate) fn layers(&self) -> &[Arc<dyn LayerOps>] {
        self.layers.as_slice()
    }

    /// Returns the parent layers for a given layer.
    pub(crate) fn get_layer_parent(&self, digest: &Digest) -> LayerDependencies {
        let parents = self
            .layers
            .rsplit(|layer| layer.digest() == digest)
            .next()
            .map(|layer| layer.to_vec())
            .unwrap_or_default();

        LayerDependencies::new(digest.clone(), ContainerImage::new(parents))
    }

    /// Extracts all layers in the image.
    pub(crate) async fn extract_all(&self) -> MicrosandboxResult<()> {
        #[cfg(feature = "cli")]
        let extract_layers_sp = term::create_spinner(
            EXTRACT_LAYERS_MSG.to_string(),
            None,
            Some(self.layers.len() as u64),
        );

        let extraction_futures = self.layers.iter().map(|layer| {
            #[cfg(feature = "cli")]
            let pb = extract_layers_sp.clone();

            async move {
                let parent_layers = self.get_layer_parent(layer.digest());
                let result = layer.extract(parent_layers).await;
                if let Err(err) = &result {
                    tracing::error!(?err, "Extracting failed. Cleaning up extracted artifacts");
                    layer.cleanup_extracted().await?;
                }

                #[cfg(feature = "cli")]
                pb.inc(1);
                result
            }
        });

        // Wait for all extractions to complete
        for result in future::join_all(extraction_futures).await {
            result?;
        }

        #[cfg(feature = "cli")]
        extract_layers_sp.finish();

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::oci::mocks::mock_registry_and_db;
    use microsandbox_utils::EXTRACTED_LAYER_SUFFIX;
    use tokio::fs;

    /// Helper function to verify that all expected nginx files exist in the extracted layers
    pub(super) async fn verify_nginx_files(layers_dir: impl AsRef<Path>) -> MicrosandboxResult<()> {
        let mut found_nginx_conf = false;
        let mut found_default_conf = false;
        let mut found_nginx_binary = false;

        // Check each extracted layer directory for nginx files
        let mut entries = fs::read_dir(layers_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(EXTRACTED_LAYER_SUFFIX)
            {
                continue;
            }

            let layer_path = entry.path();
            tracing::info!("checking layer: {}", layer_path.display());

            // Check for nginx.conf
            let nginx_conf = layer_path.join("etc").join("nginx").join("nginx.conf");
            if nginx_conf.exists() {
                found_nginx_conf = true;
                tracing::info!("found nginx.conf at {}", nginx_conf.display());
            }

            // Check for default.conf
            let default_conf = layer_path
                .join("etc")
                .join("nginx")
                .join("conf.d")
                .join("default.conf");
            if default_conf.exists() {
                found_default_conf = true;
                tracing::info!("found default.conf at {}", default_conf.display());
            }

            // Check for nginx binary
            let nginx_binary = layer_path.join("usr").join("sbin").join("nginx");
            if nginx_binary.exists() {
                found_nginx_binary = true;
                tracing::info!("found nginx binary at {}", nginx_binary.display());
            }

            // If we found all files, we can stop checking
            if found_nginx_conf && found_default_conf && found_nginx_binary {
                break;
            }
        }

        // Assert that we found all the expected files
        assert!(
            found_nginx_conf,
            "nginx.conf should exist in one of the layers"
        );
        assert!(
            found_default_conf,
            "default.conf should exist in one of the layers"
        );
        assert!(
            found_nginx_binary,
            "nginx binary should exist in one of the layers"
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[ignore = "makes network requests to Docker registry to pull an image"]
    async fn test_image_extraction() -> MicrosandboxResult<()> {
        let image_ref: Reference = "docker.io/library/nginx:stable-alpine".parse().unwrap();
        let (registry, db, layers_dir) = mock_registry_and_db().await;
        let download_dir = layers_dir.path().join("download");
        let extracted_dir = layers_dir.path().join("extracted");

        // Verify image exists in database after pulling
        registry.pull_image(&image_ref).await?;
        let image_exists = db::image_exists(&db, &image_ref.to_string()).await?;
        assert!(image_exists, "Image should exist in database");

        // Verify layers directory exists and contains extracted layers
        assert!(download_dir.exists(), "Layers directory should exist");
        let mut entries = fs::read_dir(&extracted_dir).await?;
        let mut found_extracted_layers = false;
        while let Some(entry) = entries.next_entry().await? {
            if entry
                .file_name()
                .to_string_lossy()
                .ends_with(EXTRACTED_LAYER_SUFFIX)
            {
                found_extracted_layers = true;
                assert!(
                    entry.path().is_dir(),
                    "Extracted layer path should be a directory"
                );
            }
        }
        assert!(
            found_extracted_layers,
            "Should have found extracted layer directories"
        );

        // Verify nginx files exist in the extracted layers
        verify_nginx_files(&extracted_dir).await?;

        Ok(())
    }
}
