use microsandbox::MicrosandboxError;
use napi::Status;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a `MicrosandboxError` into a `napi::Error` with a typed code string.
pub fn to_napi_error(err: MicrosandboxError) -> napi::Error {
    let code = error_type_str(&err);
    napi::Error::new(Status::GenericFailure, format!("[{code}] {err}"))
}

/// Return a string tag for the error variant, used as the JS error `code` field.
fn error_type_str(err: &MicrosandboxError) -> &'static str {
    match err {
        MicrosandboxError::Io(_) => "Io",
        MicrosandboxError::Http(_) => "Http",
        MicrosandboxError::LibkrunfwNotFound(_) => "LibkrunfwNotFound",
        MicrosandboxError::Database(_) => "Database",
        MicrosandboxError::InvalidConfig(_) => "InvalidConfig",
        MicrosandboxError::SandboxNotFound(_) => "SandboxNotFound",
        MicrosandboxError::SandboxStillRunning(_) => "SandboxStillRunning",
        MicrosandboxError::Runtime(_) => "Runtime",
        MicrosandboxError::BootStart { .. } => "BootStart",
        MicrosandboxError::Json(_) => "Json",
        MicrosandboxError::Protocol(_) => "Protocol",
        MicrosandboxError::Nix(_) => "Nix",
        MicrosandboxError::ExecTimeout(_) => "ExecTimeout",
        MicrosandboxError::ExecFailed(_) => "ExecFailed",
        MicrosandboxError::Terminal(_) => "Terminal",
        MicrosandboxError::SandboxFs(_) => "SandboxFs",
        MicrosandboxError::ImageNotFound(_) => "ImageNotFound",
        MicrosandboxError::ImageInUse(_) => "ImageInUse",
        MicrosandboxError::VolumeNotFound(_) => "VolumeNotFound",
        MicrosandboxError::VolumeAlreadyExists(_) => "VolumeAlreadyExists",
        MicrosandboxError::Image(_) => "Image",
        MicrosandboxError::NetworkBuilder(_) => "NetworkBuilder",
        MicrosandboxError::PatchFailed(_) => "PatchFailed",
        MicrosandboxError::SnapshotNotFound(_) => "SnapshotNotFound",
        MicrosandboxError::SnapshotAlreadyExists(_) => "SnapshotAlreadyExists",
        MicrosandboxError::SnapshotSandboxRunning(_) => "SnapshotSandboxRunning",
        MicrosandboxError::SnapshotImageMissing(_) => "SnapshotImageMissing",
        MicrosandboxError::SnapshotIntegrity(_) => "SnapshotIntegrity",
        MicrosandboxError::Custom(_) => "Custom",
    }
}
