//! Pull progress reporting.

use std::sync::Arc;

use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default channel capacity.
const DEFAULT_PROGRESS_CHANNEL_CAPACITY: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Progress events emitted during image pull and EROFS materialization.
#[derive(Debug, Clone)]
pub enum PullProgress {
    /// Resolving the image reference.
    Resolving {
        /// The image reference being resolved.
        reference: Arc<str>,
    },

    /// Manifest parsed. Layer count and total sizes now known.
    Resolved {
        /// The image reference.
        reference: Arc<str>,
        /// Resolved manifest digest.
        manifest_digest: Arc<str>,
        /// Number of layers.
        layer_count: usize,
        /// Sum of compressed layer sizes. `None` if manifest omits sizes.
        total_download_bytes: Option<u64>,
    },

    /// Byte-level download progress for a single layer.
    LayerDownloadProgress {
        /// Layer index (0-based).
        layer_index: usize,
        /// Layer digest.
        digest: Arc<str>,
        /// Bytes downloaded so far.
        downloaded_bytes: u64,
        /// Total bytes (if known).
        total_bytes: Option<u64>,
    },

    /// A single layer download completed and verified.
    LayerDownloadComplete {
        /// Layer index.
        layer_index: usize,
        /// Layer digest.
        digest: Arc<str>,
        /// Total downloaded bytes.
        downloaded_bytes: u64,
    },

    /// Layer download completed and the blob is being verified.
    LayerDownloadVerifying {
        /// Layer index.
        layer_index: usize,
        /// Layer digest.
        digest: Arc<str>,
    },

    /// Layer EROFS materialization started.
    LayerMaterializeStarted {
        /// Layer index.
        layer_index: usize,
        /// Layer diff ID.
        diff_id: Arc<str>,
    },

    /// Byte-level materialization progress for a single layer.
    LayerMaterializeProgress {
        /// Layer index (0-based).
        layer_index: usize,
        /// Bytes read so far.
        bytes_read: u64,
        /// Total bytes.
        total_bytes: u64,
    },

    /// Layer tar ingest is complete and the EROFS image is being written.
    LayerMaterializeWriting {
        /// Layer index.
        layer_index: usize,
    },

    /// Layer EROFS materialization completed.
    LayerMaterializeComplete {
        /// Layer index.
        layer_index: usize,
        /// Layer diff ID.
        diff_id: Arc<str>,
    },

    /// Flat mode: layer merge started.
    FlatMergeStarted {
        /// Number of layers being merged.
        layer_count: usize,
    },

    /// Flat mode: flat.erofs written.
    FlatMergeComplete {
        /// Manifest digest of the flat image.
        manifest_digest: Arc<str>,
    },

    /// Entire image pull completed.
    Complete {
        /// The image reference.
        reference: Arc<str>,
        /// Number of layers.
        layer_count: usize,
    },
}

/// Receiver for progress events.
pub struct PullProgressHandle {
    rx: mpsc::Receiver<PullProgress>,
}

/// Emits progress events. Uses `try_send` — never blocks downloads.
#[derive(Clone)]
pub struct PullProgressSender {
    tx: mpsc::Sender<PullProgress>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PullProgressHandle {
    /// Receive the next event. Returns `None` when the pull completes.
    pub async fn recv(&mut self) -> Option<PullProgress> {
        self.rx.recv().await
    }

    /// Convert into the underlying receiver for use with `tokio::select!`.
    pub fn into_receiver(self) -> mpsc::Receiver<PullProgress> {
        self.rx
    }
}

impl PullProgressSender {
    /// Emit a progress event. Silently discards if receiver is full or dropped.
    pub fn send(&self, event: PullProgress) {
        let _ = self.tx.try_send(event);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a progress channel pair.
pub fn progress_channel() -> (PullProgressHandle, PullProgressSender) {
    let (tx, rx) = mpsc::channel(DEFAULT_PROGRESS_CHANNEL_CAPACITY);
    (PullProgressHandle { rx }, PullProgressSender { tx })
}
