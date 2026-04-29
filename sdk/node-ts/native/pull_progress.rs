use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use microsandbox::sandbox::{PullProgress as RustPullProgress, PullProgressHandle};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One progress event emitted during image pull and EROFS materialization.
///
/// `kind` discriminates the event; the per-variant fields below are
/// `null` when not applicable to that kind.
#[derive(Clone)]
#[napi(object, js_name = "PullProgressEvent")]
pub struct PullProgressEvent {
    /// Event kind: one of
    /// `"resolving" | "resolved" | "layerDownloadProgress" |
    ///  "layerDownloadComplete" | "layerDownloadVerifying" |
    ///  "layerMaterializeStarted" | "layerMaterializeProgress" |
    ///  "layerMaterializeWriting" | "layerMaterializeComplete" |
    ///  "stitchMergingTrees" | "stitchWritingFsmeta" |
    ///  "stitchWritingVmdk" | "stitchComplete" | "complete"`.
    pub kind: String,
    pub reference: Option<String>,
    pub manifest_digest: Option<String>,
    pub layer_count: Option<u32>,
    pub total_download_bytes: Option<f64>,
    pub layer_index: Option<u32>,
    pub digest: Option<String>,
    pub diff_id: Option<String>,
    pub downloaded_bytes: Option<f64>,
    pub total_bytes: Option<f64>,
    pub bytes_read: Option<f64>,
}

/// Streaming subscription for image-pull progress events.
///
/// Supports both manual `recv()` and `for await...of` iteration:
/// ```js
/// const { sandbox, progress } = await Sandbox.builder("demo")
///   .image("alpine:latest")
///   .createWithPullProgress();
/// for await (const ev of progress) {
///   if (ev.kind === "layerDownloadProgress") { … }
/// }
/// const sb = await sandbox; // resolves once create finishes
/// ```
#[derive(Clone)]
#[napi(async_iterator, js_name = "PullProgressStream")]
pub struct JsPullProgressStream {
    inner: Arc<Mutex<Option<PullProgressHandle>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsPullProgressStream {
    /// Receive the next progress event. Returns `null` when the pull
    /// completes (channel closed).
    #[napi]
    pub async fn recv(&self) -> Result<Option<PullProgressEvent>> {
        let mut guard = self.inner.lock().await;
        let Some(handle) = guard.as_mut() else {
            return Ok(None);
        };
        Ok(handle.recv().await.map(progress_to_js))
    }
}

#[napi]
impl AsyncGenerator for JsPullProgressStream {
    type Yield = PullProgressEvent;
    type Next = ();
    type Return = ();

    fn next(
        &mut self,
        _value: Option<Self::Next>,
    ) -> impl std::future::Future<Output = Result<Option<Self::Yield>>> + Send + 'static {
        let inner = Arc::clone(&self.inner);
        async move {
            let mut guard = inner.lock().await;
            let Some(handle) = guard.as_mut() else {
                return Ok(None);
            };
            Ok(handle.recv().await.map(progress_to_js))
        }
    }
}

impl JsPullProgressStream {
    pub fn from_handle(handle: PullProgressHandle) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(handle))),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn progress_to_js(ev: RustPullProgress) -> PullProgressEvent {
    let blank = || PullProgressEvent {
        kind: String::new(),
        reference: None,
        manifest_digest: None,
        layer_count: None,
        total_download_bytes: None,
        layer_index: None,
        digest: None,
        diff_id: None,
        downloaded_bytes: None,
        total_bytes: None,
        bytes_read: None,
    };
    match ev {
        RustPullProgress::Resolving { reference } => PullProgressEvent {
            kind: "resolving".into(),
            reference: Some(reference.to_string()),
            ..blank()
        },
        RustPullProgress::Resolved {
            reference,
            manifest_digest,
            layer_count,
            total_download_bytes,
        } => PullProgressEvent {
            kind: "resolved".into(),
            reference: Some(reference.to_string()),
            manifest_digest: Some(manifest_digest.to_string()),
            layer_count: Some(layer_count as u32),
            total_download_bytes: total_download_bytes.map(|b| b as f64),
            ..blank()
        },
        RustPullProgress::LayerDownloadProgress {
            layer_index,
            digest,
            downloaded_bytes,
            total_bytes,
        } => PullProgressEvent {
            kind: "layerDownloadProgress".into(),
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            downloaded_bytes: Some(downloaded_bytes as f64),
            total_bytes: total_bytes.map(|b| b as f64),
            ..blank()
        },
        RustPullProgress::LayerDownloadComplete {
            layer_index,
            digest,
            downloaded_bytes,
        } => PullProgressEvent {
            kind: "layerDownloadComplete".into(),
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            downloaded_bytes: Some(downloaded_bytes as f64),
            ..blank()
        },
        RustPullProgress::LayerDownloadVerifying {
            layer_index,
            digest,
        } => PullProgressEvent {
            kind: "layerDownloadVerifying".into(),
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            ..blank()
        },
        RustPullProgress::LayerMaterializeStarted {
            layer_index,
            diff_id,
        } => PullProgressEvent {
            kind: "layerMaterializeStarted".into(),
            layer_index: Some(layer_index as u32),
            diff_id: Some(diff_id.to_string()),
            ..blank()
        },
        RustPullProgress::LayerMaterializeProgress {
            layer_index,
            bytes_read,
            total_bytes,
        } => PullProgressEvent {
            kind: "layerMaterializeProgress".into(),
            layer_index: Some(layer_index as u32),
            bytes_read: Some(bytes_read as f64),
            total_bytes: Some(total_bytes as f64),
            ..blank()
        },
        RustPullProgress::LayerMaterializeWriting { layer_index } => PullProgressEvent {
            kind: "layerMaterializeWriting".into(),
            layer_index: Some(layer_index as u32),
            ..blank()
        },
        RustPullProgress::LayerMaterializeComplete {
            layer_index,
            diff_id,
        } => PullProgressEvent {
            kind: "layerMaterializeComplete".into(),
            layer_index: Some(layer_index as u32),
            diff_id: Some(diff_id.to_string()),
            ..blank()
        },
        RustPullProgress::StitchMergingTrees { layer_count } => PullProgressEvent {
            kind: "stitchMergingTrees".into(),
            layer_count: Some(layer_count as u32),
            ..blank()
        },
        RustPullProgress::StitchWritingFsmeta => PullProgressEvent {
            kind: "stitchWritingFsmeta".into(),
            ..blank()
        },
        RustPullProgress::StitchWritingVmdk => PullProgressEvent {
            kind: "stitchWritingVmdk".into(),
            ..blank()
        },
        RustPullProgress::StitchComplete => PullProgressEvent {
            kind: "stitchComplete".into(),
            ..blank()
        },
        RustPullProgress::Complete {
            reference,
            layer_count,
        } => PullProgressEvent {
            kind: "complete".into(),
            reference: Some(reference.to_string()),
            layer_count: Some(layer_count as u32),
            ..blank()
        },
    }
}
