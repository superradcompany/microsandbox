use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox::sandbox::{Patch as RustPatch, PatchBuilder as RustPatchBuilder};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Rootfs patch produced by `PatchBuilder.build()`. Flat representation
/// of the `Patch` enum: `kind` discriminator + per-variant fields.
#[derive(Clone)]
#[napi(object, js_name = "Patch")]
pub struct JsBuiltPatch {
    /// `"text" | "file" | "copyFile" | "copyDir" | "symlink" | "mkdir" | "remove" | "append"`.
    pub kind: String,
    /// Absolute guest path (text/file/mkdir/remove/append).
    pub path: Option<String>,
    /// Host source path (copyFile/copyDir).
    pub src: Option<String>,
    /// Guest destination path (copyFile/copyDir).
    pub dst: Option<String>,
    /// Symlink target.
    pub target: Option<String>,
    /// Symlink link path.
    pub link: Option<String>,
    /// Text content (text/append).
    pub content: Option<String>,
    /// Raw byte content (file).
    pub content_bytes: Option<Vec<u8>>,
    /// File / directory permissions.
    pub mode: Option<u32>,
    /// Allow replacing an existing path.
    pub replace: Option<bool>,
}

/// Optional knobs accepted by `text`, `file`, `copyFile`.
#[napi(object, js_name = "PatchFileOptions")]
pub struct JsPatchFileOptions {
    pub mode: Option<u32>,
    pub replace: Option<bool>,
}

/// Optional knobs accepted by `copyDir`, `symlink`.
#[napi(object, js_name = "PatchReplaceOnly")]
pub struct JsPatchReplaceOnly {
    pub replace: Option<bool>,
}

/// Optional knobs accepted by `mkdir`.
#[napi(object, js_name = "PatchModeOnly")]
pub struct JsPatchModeOnly {
    pub mode: Option<u32>,
}

/// Fluent builder for an ordered list of pre-boot rootfs patches.
#[napi(js_name = "PatchBuilder")]
pub struct JsPatchBuilder {
    inner: Option<RustPatchBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsPatchBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustPatchBuilder::new()),
        }
    }

    /// Write a text file (UTF-8) at `path`.
    #[napi]
    pub fn text(
        &mut self,
        path: String,
        content: String,
        opts: Option<JsPatchFileOptions>,
    ) -> &Self {
        let prev = self.take_inner();
        let opts = opts.unwrap_or(JsPatchFileOptions {
            mode: None,
            replace: None,
        });
        self.inner = Some(prev.text(path, content, opts.mode, opts.replace.unwrap_or(false)));
        self
    }

    /// Write raw bytes at `path`.
    #[napi]
    pub fn file(
        &mut self,
        path: String,
        content: Buffer,
        opts: Option<JsPatchFileOptions>,
    ) -> &Self {
        let prev = self.take_inner();
        let opts = opts.unwrap_or(JsPatchFileOptions {
            mode: None,
            replace: None,
        });
        self.inner = Some(prev.file(
            path,
            content.to_vec(),
            opts.mode,
            opts.replace.unwrap_or(false),
        ));
        self
    }

    /// Copy a host file into the rootfs at `dst`.
    #[napi(js_name = "copyFile")]
    pub fn copy_file(
        &mut self,
        src: String,
        dst: String,
        opts: Option<JsPatchFileOptions>,
    ) -> &Self {
        let prev = self.take_inner();
        let opts = opts.unwrap_or(JsPatchFileOptions {
            mode: None,
            replace: None,
        });
        self.inner = Some(prev.copy_file(
            PathBuf::from(src),
            dst,
            opts.mode,
            opts.replace.unwrap_or(false),
        ));
        self
    }

    /// Copy a host directory into the rootfs at `dst`.
    #[napi(js_name = "copyDir")]
    pub fn copy_dir(
        &mut self,
        src: String,
        dst: String,
        opts: Option<JsPatchReplaceOnly>,
    ) -> &Self {
        let prev = self.take_inner();
        let replace = opts.and_then(|o| o.replace).unwrap_or(false);
        self.inner = Some(prev.copy_dir(PathBuf::from(src), dst, replace));
        self
    }

    /// Create a symlink at `link` pointing to `target`.
    #[napi]
    pub fn symlink(
        &mut self,
        target: String,
        link: String,
        opts: Option<JsPatchReplaceOnly>,
    ) -> &Self {
        let prev = self.take_inner();
        let replace = opts.and_then(|o| o.replace).unwrap_or(false);
        self.inner = Some(prev.symlink(target, link, replace));
        self
    }

    /// Create a directory (idempotent).
    #[napi]
    pub fn mkdir(&mut self, path: String, opts: Option<JsPatchModeOnly>) -> &Self {
        let prev = self.take_inner();
        let mode = opts.and_then(|o| o.mode);
        self.inner = Some(prev.mkdir(path, mode));
        self
    }

    /// Remove a file or directory (idempotent).
    #[napi]
    pub fn remove(&mut self, path: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.remove(path));
        self
    }

    /// Append text to an existing file.
    #[napi]
    pub fn append(&mut self, path: String, content: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.append(path, content));
        self
    }

    /// Materialize into the ordered list of patches.
    #[napi]
    pub fn build(&mut self) -> Result<Vec<JsBuiltPatch>> {
        let patches = self.take_built()?;
        Ok(patches.into_iter().map(to_js_patch).collect())
    }
}

impl JsPatchBuilder {
    fn take_inner(&mut self) -> RustPatchBuilder {
        self.inner
            .take()
            .expect("PatchBuilder used after .build() consumed it")
    }

    /// Internal: extract the ordered patches. Used by `SandboxBuilder.patch()`.
    pub(crate) fn take_built(&mut self) -> Result<Vec<RustPatch>> {
        let b = self.inner.take().ok_or_else(|| {
            napi::Error::from_reason("PatchBuilder.build() called more than once")
        })?;
        Ok(b.build())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a JS-shape `Patch` (`{ kind, path?, content?, ... }`) into a
/// Rust `microsandbox::sandbox::Patch`. Used by `SandboxBuilder.addPatch`.
pub(crate) fn js_patch_to_rust(p: JsBuiltPatch) -> Result<RustPatch> {
    use std::path::PathBuf;
    let need = |opt: Option<String>, field: &str| {
        opt.ok_or_else(|| {
            napi::Error::from_reason(format!("patch kind `{}` requires `{}`", p.kind, field))
        })
    };
    match p.kind.as_str() {
        "text" => Ok(RustPatch::Text {
            path: need(p.path.clone(), "path")?,
            content: need(p.content.clone(), "content")?,
            mode: p.mode,
            replace: p.replace.unwrap_or(false),
        }),
        "file" => Ok(RustPatch::File {
            path: need(p.path.clone(), "path")?,
            content: p.content_bytes.clone().ok_or_else(|| {
                napi::Error::from_reason("patch kind `file` requires `contentBytes`")
            })?,
            mode: p.mode,
            replace: p.replace.unwrap_or(false),
        }),
        "copyFile" => Ok(RustPatch::CopyFile {
            src: PathBuf::from(need(p.src.clone(), "src")?),
            dst: need(p.dst.clone(), "dst")?,
            mode: p.mode,
            replace: p.replace.unwrap_or(false),
        }),
        "copyDir" => Ok(RustPatch::CopyDir {
            src: PathBuf::from(need(p.src.clone(), "src")?),
            dst: need(p.dst.clone(), "dst")?,
            replace: p.replace.unwrap_or(false),
        }),
        "symlink" => Ok(RustPatch::Symlink {
            target: need(p.target.clone(), "target")?,
            link: need(p.link.clone(), "link")?,
            replace: p.replace.unwrap_or(false),
        }),
        "mkdir" => Ok(RustPatch::Mkdir {
            path: need(p.path.clone(), "path")?,
            mode: p.mode,
        }),
        "remove" => Ok(RustPatch::Remove {
            path: need(p.path.clone(), "path")?,
        }),
        "append" => Ok(RustPatch::Append {
            path: need(p.path.clone(), "path")?,
            content: need(p.content.clone(), "content")?,
        }),
        other => Err(napi::Error::from_reason(format!(
            "unknown patch kind `{other}`"
        ))),
    }
}

pub(crate) fn to_js_patch(p: RustPatch) -> JsBuiltPatch {
    let blank = || JsBuiltPatch {
        kind: String::new(),
        path: None,
        src: None,
        dst: None,
        target: None,
        link: None,
        content: None,
        content_bytes: None,
        mode: None,
        replace: None,
    };
    match p {
        RustPatch::Text {
            path,
            content,
            mode,
            replace,
        } => JsBuiltPatch {
            kind: "text".into(),
            path: Some(path),
            content: Some(content),
            mode,
            replace: Some(replace),
            ..blank()
        },
        RustPatch::File {
            path,
            content,
            mode,
            replace,
        } => JsBuiltPatch {
            kind: "file".into(),
            path: Some(path),
            content_bytes: Some(content),
            mode,
            replace: Some(replace),
            ..blank()
        },
        RustPatch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => JsBuiltPatch {
            kind: "copyFile".into(),
            src: Some(src.to_string_lossy().into_owned()),
            dst: Some(dst),
            mode,
            replace: Some(replace),
            ..blank()
        },
        RustPatch::CopyDir { src, dst, replace } => JsBuiltPatch {
            kind: "copyDir".into(),
            src: Some(src.to_string_lossy().into_owned()),
            dst: Some(dst),
            replace: Some(replace),
            ..blank()
        },
        RustPatch::Symlink {
            target,
            link,
            replace,
        } => JsBuiltPatch {
            kind: "symlink".into(),
            target: Some(target),
            link: Some(link),
            replace: Some(replace),
            ..blank()
        },
        RustPatch::Mkdir { path, mode } => JsBuiltPatch {
            kind: "mkdir".into(),
            path: Some(path),
            mode,
            ..blank()
        },
        RustPatch::Remove { path } => JsBuiltPatch {
            kind: "remove".into(),
            path: Some(path),
            ..blank()
        },
        RustPatch::Append { path, content } => JsBuiltPatch {
            kind: "append".into(),
            path: Some(path),
            content: Some(content),
            ..blank()
        },
    }
}
