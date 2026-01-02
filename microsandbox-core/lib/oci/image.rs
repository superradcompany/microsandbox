//! Container image management for Microsandbox.
//!
//! This module provides functionality for managing container images from various
//! registries, and extracting their corresponding layers to the local file system.
//!
//!
//! # Usage
//!
//! ```no_run
//! use microsandbox_core::oci::Image;
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let layer_output_dir = Some(PathBuf::from("/custom/path"));
//!
//!     // Pull a single image from Docker registry
//!     Image::pull("docker.io/library/ubuntu:latest".parse().unwrap(), layer_output_dir.clone()).await?;
//!
//!     // Pull an image from the default registry (when no registry is specified in the reference)
//!     Image::pull("nginx:latest".parse().unwrap(), layer_output_dir.clone()).await?;
//!
//!     // You can set the OCI_REGISTRY_DOMAIN environment variable to specify your default registry
//!     unsafe { std::env::set_var("OCI_REGISTRY_DOMAIN", "docker.io") };
//!     Image::pull("alpine:latest".parse().unwrap(), layer_output_dir.clone()).await?;
//!
//!     // Pull an image from Docker registry and store the layers in a custom directory
//!     Image::pull("docker.io/library/ubuntu:latest".parse().unwrap(), layer_output_dir).await?;
//!
//!     Ok(())
//! }
//! ```
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

/// A bundle of layers that are related (e.g., parent layers for a given layer)
#[derive(Clone)]
pub struct Image {
    /// Layers composing the image in the correct order, where
    /// the first and last layers are the base and topmost layers, respectively.
    layers: Vec<Arc<dyn LayerOps>>,
}

impl Image {
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

        LayerDependencies::new(digest.clone(), Image::new(parents))
    }

    /// Extracts all layers in the image.
    pub(crate) async fn extract_all(&self) -> MicrosandboxResult<()> {
        #[cfg(feature = "cli")]
        let extract_layers_sp = term::create_spinner(
            "Extracting layers".to_string(),
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

    /// Pulls an image using whatever registry is configured.
    ///
    /// ## Arguments
    ///
    /// * `image` - The reference to the image to pull
    /// * `layer_extraction_dir` - The path to store the layer files. If None,
    ///                            the default layer output directory is used.
    ///
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
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::oci::mocks::mock_registry_and_db;
    use microsandbox_utils::EXTRACTED_LAYER_SUFFIX;

    use rstest::rstest;
    use tokio::fs;

    #[rstest]
    #[case(
        "docker.io/library/nginx:stable-alpine3.23",
        vec!["etc/nginx/nginx.conf", "etc/nginx/conf.d/default.conf", "usr/sbin/nginx"],
        8
    )]
    #[case(
        "us-docker.pkg.dev/google-samples/containers/gke/hello-app:1.0",
        vec!["hello-app"],
        15
    )]
    #[test_log::test(tokio::test)]
    #[ignore = "makes network requests to Docker registry to pull an image"]
    async fn test_image_extraction(
        #[case] image_ref: Reference,
        #[case] files_to_verify: Vec<&'static str>,
        #[case] expected_extracted_layers: usize,
    ) -> MicrosandboxResult<()> {
        let (registry, db, layers_dir) = mock_registry_and_db().await;
        let download_dir = layers_dir.path().join("download");
        let extracted_dir = layers_dir.path().join("extracted");

        // Verify image exists in database after pulling
        registry.pull_image(&image_ref).await?;
        let image_exists = db::image_exists(&db, &image_ref.to_string()).await?;
        assert!(image_exists, "Image should exist in database");

        // Verify layers directory exists and contains extracted layers
        let mut extracted_layers_count = 0;
        let mut extracted_dir_entries = fs::read_dir(&extracted_dir).await?;
        let mut files_not_found = HashSet::<&str>::from_iter(files_to_verify);
        assert!(download_dir.exists(), "Layers directory should exist");

        while let Some(entry) = extracted_dir_entries.next_entry().await? {
            let entry_name = entry.file_name().to_string_lossy().to_string();
            if entry_name.ends_with(EXTRACTED_LAYER_SUFFIX) && entry.path().is_dir() {
                extracted_layers_count += 1;
            }

            for file in files_not_found.clone() {
                if entry.path().join(file).exists() {
                    files_not_found.remove(file);
                }
            }
        }
        assert!(
            files_not_found.is_empty(),
            "not all files could be found: {:?}",
            files_not_found
        );

        assert_eq!(
            extracted_layers_count, expected_extracted_layers,
            "Extracted layer should be complete"
        );

        Ok(())
    }
}
