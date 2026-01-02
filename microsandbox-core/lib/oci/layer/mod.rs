pub(crate) mod extraction;
mod progress;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use async_compression::tokio::bufread::GzipDecoder;
use async_trait::async_trait;

use microsandbox_utils::EXTRACTED_LAYER_SUFFIX;
use oci_spec::image::Digest;
use tokio::{
    fs,
    io::BufReader,
    sync::{Mutex, OwnedMutexGuard},
};
use tokio_tar::Archive;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    oci::{
        extraction::extract_tar_with_ownership_override, global_cache::GlobalCacheOps, image::Image,
    },
};

#[async_trait]
pub(crate) trait LayerOps: Send + Sync {
    fn global_layer_ops(&self) -> &dyn GlobalCacheOps;

    /// Get the digest of the layer.
    fn digest(&self) -> &Digest;

    /// Get the path to the layer tar file.
    fn tar_path(&self) -> PathBuf {
        self.global_layer_ops()
            .tar_download_dir()
            .join(self.digest().to_string())
            .with_extension("tar")
    }

    /// Gets the size of the layer tar file.
    ///
    /// ## Returns
    ///
    /// The size of the layer tar file in bytes, or None if the file does not exist.
    ///
    fn get_tar_size(&self) -> Option<u64> {
        let tar_path = self.tar_path();
        if !tar_path.exists() {
            return None;
        }

        let len = tar_path
            .metadata()
            .expect("Failed to get layer file metadata")
            .len();

        Some(len)
    }

    /// The directory the layer will be extracted to.
    ///
    /// This follows after the format of `<layer-name>.extracted`.
    fn extracted_layer_dir(&self) -> PathBuf {
        let file_name = self.digest().to_string();
        self.global_layer_ops()
            .extracted_layers_dir()
            .join(format!("{}.{}", file_name, EXTRACTED_LAYER_SUFFIX))
    }

    /// Checks if the layer has been extracted.
    async fn extracted(&self) -> MicrosandboxResult<(bool, OwnedMutexGuard<()>)>;

    /// Cleans up the extracted layer directory if it exists.
    async fn cleanup_extracted(&self) -> MicrosandboxResult<()>;

    /// Extracts the layer.
    async fn extract(&self, parent: LayerDependencies) -> MicrosandboxResult<()>;

    /// Search for directory in the current layer
    ///
    /// ## Arguments
    ///
    /// * `path_in_tar` - The path in the tar file.
    ///
    /// ## Returns
    ///
    /// If the directory is found, the canonical path to the directory in the extracted
    /// layer directory is returned. Otherwise, returns None.
    async fn find_dir(&self, path_in_tar: &PathBuf) -> Option<PathBuf>;
}

#[derive(Clone)]
pub struct Layer {
    global_layer_ops: Arc<dyn GlobalCacheOps>,
    lock: Arc<Mutex<()>>,
    digest: Digest,
}

impl Layer {
    pub fn new(global_layer_ops: Arc<dyn GlobalCacheOps>, digest: Digest) -> Self {
        Self {
            global_layer_ops,
            digest,
            lock: Arc::new(Mutex::new(())),
        }
    }
}

#[async_trait]
impl LayerOps for Layer {
    fn global_layer_ops(&self) -> &dyn GlobalCacheOps {
        self.global_layer_ops.as_ref()
    }

    fn digest(&self) -> &Digest {
        &self.digest
    }

    async fn extracted(&self) -> MicrosandboxResult<(bool, OwnedMutexGuard<()>)> {
        let guard = self.lock.clone().lock_owned().await;
        let dir = self.extracted_layer_dir();
        if !dir.exists() {
            return Ok((false, guard));
        }

        // Check that the layer directory actually has content
        let mut read_dir = fs::read_dir(&dir).await?;
        let next = read_dir.next_entry().await;
        if next.is_ok() {
            tracing::debug!(digest = %self.digest(), "layer directory has content");
            return Ok((true, guard));
        }

        tracing::warn!(digest = %self.digest(), "layer exists but is empty");
        Ok((false, guard))
    }

    async fn cleanup_extracted(&self) -> MicrosandboxResult<()> {
        let _guard = self.lock.lock().await;
        let layer_path = self.extracted_layer_dir();
        if layer_path.exists() {
            tracing::debug!(layer_path = %layer_path.display(), "Cleaning up extracted layer");

            tokio::fs::remove_dir_all(&layer_path)
                .await
                .inspect_err(|err| {
                    tracing::error!(?err, "Failed to clean extracted layer");
                })?;
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(
        extract_dir = %self.extracted_layer_dir().display(),
        digest = %self.digest(),
    ))]
    async fn extract(&self, parent: LayerDependencies) -> MicrosandboxResult<()> {
        assert_eq!(self.digest(), parent.digest());
        let (false, _guard) = self.extracted().await? else {
            return Ok(());
        };

        let layer_path = self.tar_path();
        let digest = self.digest().clone();
        let extract_dir = self.extracted_layer_dir();
        fs::create_dir_all(&extract_dir).await.map_err(|source| {
            MicrosandboxError::LayerHandling {
                layer: digest.to_string(),
                source,
            }
        })?;

        tracing::info!("Extracting layer");

        let file = tokio::fs::File::open(&layer_path).await?;
        #[cfg(feature = "cli")]
        let (file, pb) = {
            use crate::oci::layer::progress::{ProgressReader, build_progress_bar};

            let total_bytes = fs::metadata(&layer_path).await?.len();
            let bar = build_progress_bar(total_bytes, &digest.digest()[..8]);
            let bar_clone = bar.clone();
            (ProgressReader { inner: file, bar }, bar_clone)
        };

        let mut archive = Archive::new(GzipDecoder::new(BufReader::new(file)));
        extract_tar_with_ownership_override(&mut archive, &extract_dir, parent)
            .await
            .map_err(|e| MicrosandboxError::LayerExtraction(format!("{e:?}")))?;

        #[cfg(feature = "cli")]
        pb.finish_and_clear();

        tracing::info!("Successfully extracted layer");
        Ok(())
    }

    async fn find_dir(&self, path: &PathBuf) -> Option<PathBuf> {
        let canonical_path = self.extracted_layer_dir().join(path);
        if canonical_path.exists() && canonical_path.is_dir() {
            return Some(canonical_path);
        }

        None
    }
}

/// Abstraction around all dependencies of a layer i.e. all
/// layers upon which the current layer depends on.
#[derive(Clone)]
pub(crate) struct LayerDependencies {
    /// The layer digest in focus.
    layer: Digest,
    /// The image this layer belongs to.
    image: Image,
}

impl LayerDependencies {
    /// Creates a new layer dependencies.
    ///
    /// ## Arguments
    ///
    /// * `layer` - The layer digest in focus.
    /// * `image` - The image this layer belongs to.
    pub(crate) fn new(layer: Digest, image: Image) -> Self {
        Self { layer, image }
    }

    /// Gets the digest of the layer in focus.
    pub(crate) fn digest(&self) -> &Digest {
        &self.layer
    }

    /// Search for the file in all parent layers in descending order.
    ///
    /// ## Arguments
    ///
    /// * `path` - The path to search for.
    pub(crate) async fn find_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> MicrosandboxResult<Option<(Digest, PathBuf)>> {
        let path = path.as_ref().to_path_buf();

        // iterate over layers in reverse order
        // if the layer hasn't been extracted yet, extract it
        // if the file is found in the layer, return the layer digest and the path to the file
        for layer in self.image.layers().iter() {
            layer
                .extract(self.image.get_layer_parent(layer.digest()))
                .await?;

            if let Some(path) = layer.find_dir(&path).await {
                return Ok(Some((layer.digest().clone(), path)));
            }
        }

        Ok(None)
    }
}
