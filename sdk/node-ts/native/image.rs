use microsandbox::image as msb_image;
use microsandbox::image::{ImageDetail, ImageHandle};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lightweight handle to a cached image.
#[napi(js_name = "ImageHandle")]
pub struct JsImageHandle {
    inner: ImageHandle,
}

/// OCI config fields extracted from the database.
#[napi(object)]
pub struct ImageConfigDetail {
    pub digest: String,
    pub env: Vec<String>,
    pub cmd: Option<Vec<String>>,
    pub entrypoint: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub labels_json: Option<String>,
    pub stop_signal: Option<String>,
}

/// Metadata for a single layer.
#[napi(object)]
pub struct ImageLayerDetail {
    pub diff_id: String,
    pub blob_digest: String,
    pub media_type: Option<String>,
    pub compressed_size_bytes: Option<f64>,
    pub erofs_size_bytes: Option<f64>,
    pub position: i32,
}

/// Full image detail (config + layers + handle metadata).
#[napi(object)]
pub struct ImageDetailJs {
    pub reference: String,
    pub manifest_digest: Option<String>,
    pub architecture: Option<String>,
    pub os: Option<String>,
    pub layer_count: f64,
    pub size_bytes: Option<f64>,
    pub created_at: Option<f64>,
    pub last_used_at: Option<f64>,
    pub config: Option<ImageConfigDetail>,
    pub layers: Vec<ImageLayerDetail>,
}

/// Lightweight image info as returned by `imageList`.
#[napi(object)]
pub struct ImageInfo {
    pub reference: String,
    pub manifest_digest: Option<String>,
    pub architecture: Option<String>,
    pub os: Option<String>,
    pub layer_count: f64,
    pub size_bytes: Option<f64>,
    pub created_at: Option<f64>,
    pub last_used_at: Option<f64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsImageHandle {
    #[napi(getter)]
    pub fn reference(&self) -> String {
        self.inner.reference().to_string()
    }

    #[napi(getter)]
    pub fn size_bytes(&self) -> Option<f64> {
        self.inner.size_bytes().map(|n| n as f64)
    }

    #[napi(getter)]
    pub fn manifest_digest(&self) -> Option<String> {
        self.inner.manifest_digest().map(str::to_string)
    }

    #[napi(getter)]
    pub fn architecture(&self) -> Option<String> {
        self.inner.architecture().map(str::to_string)
    }

    #[napi(getter)]
    pub fn os(&self) -> Option<String> {
        self.inner.os().map(str::to_string)
    }

    #[napi(getter)]
    pub fn layer_count(&self) -> f64 {
        self.inner.layer_count() as f64
    }

    #[napi(getter)]
    pub fn last_used_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.last_used_at())
    }

    #[napi(getter)]
    pub fn created_at(&self) -> Option<f64> {
        opt_datetime_to_ms(&self.inner.created_at())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Look up a cached image by reference.
#[napi(js_name = "imageGet")]
pub async fn image_get(reference: String) -> Result<JsImageHandle> {
    let inner = msb_image::Image::get(&reference)
        .await
        .map_err(to_napi_error)?;
    Ok(JsImageHandle { inner })
}

/// List all cached images.
#[napi(js_name = "imageList")]
pub async fn image_list() -> Result<Vec<ImageInfo>> {
    let handles = msb_image::Image::list().await.map_err(to_napi_error)?;
    Ok(handles.iter().map(image_handle_to_info).collect())
}

/// Full inspect (config + layers).
#[napi(js_name = "imageInspect")]
pub async fn image_inspect(reference: String) -> Result<ImageDetailJs> {
    let detail = msb_image::Image::inspect(&reference)
        .await
        .map_err(to_napi_error)?;
    Ok(image_detail_to_js(detail))
}

/// Remove a cached image. Pass `force = true` to delete even when a
/// sandbox references it.
#[napi(js_name = "imageRemove")]
pub async fn image_remove(reference: String, force: Option<bool>) -> Result<()> {
    msb_image::Image::remove(&reference, force.unwrap_or(false))
        .await
        .map_err(to_napi_error)
}

/// Garbage-collect orphaned layers. Returns the number reclaimed.
#[napi(js_name = "imageGcLayers")]
pub async fn image_gc_layers() -> Result<u32> {
    msb_image::Image::gc_layers().await.map_err(to_napi_error)
}

/// Garbage-collect everything reclaimable. Returns the number reclaimed.
#[napi(js_name = "imageGc")]
pub async fn image_gc() -> Result<u32> {
    msb_image::Image::gc().await.map_err(to_napi_error)
}

fn image_handle_to_info(h: &ImageHandle) -> ImageInfo {
    ImageInfo {
        reference: h.reference().to_string(),
        manifest_digest: h.manifest_digest().map(str::to_string),
        architecture: h.architecture().map(str::to_string),
        os: h.os().map(str::to_string),
        layer_count: h.layer_count() as f64,
        size_bytes: h.size_bytes().map(|n| n as f64),
        created_at: opt_datetime_to_ms(&h.created_at()),
        last_used_at: opt_datetime_to_ms(&h.last_used_at()),
    }
}

fn image_detail_to_js(d: ImageDetail) -> ImageDetailJs {
    let h = &d.handle;
    let config = d.config.as_ref().map(|c| ImageConfigDetail {
        digest: c.digest.clone(),
        env: c.env.clone(),
        cmd: c.cmd.clone(),
        entrypoint: c.entrypoint.clone(),
        working_dir: c.working_dir.clone(),
        user: c.user.clone(),
        labels_json: c.labels.as_ref().map(|v| v.to_string()),
        stop_signal: c.stop_signal.clone(),
    });
    let layers = d
        .layers
        .iter()
        .map(|l| ImageLayerDetail {
            diff_id: l.diff_id.clone(),
            blob_digest: l.blob_digest.clone(),
            media_type: l.media_type.clone(),
            compressed_size_bytes: l.compressed_size_bytes.map(|n| n as f64),
            erofs_size_bytes: l.erofs_size_bytes.map(|n| n as f64),
            position: l.position,
        })
        .collect();
    ImageDetailJs {
        reference: h.reference().to_string(),
        manifest_digest: h.manifest_digest().map(str::to_string),
        architecture: h.architecture().map(str::to_string),
        os: h.os().map(str::to_string),
        layer_count: h.layer_count() as f64,
        size_bytes: h.size_bytes().map(|n| n as f64),
        created_at: opt_datetime_to_ms(&h.created_at()),
        last_used_at: opt_datetime_to_ms(&h.last_used_at()),
        config,
        layers,
    }
}
