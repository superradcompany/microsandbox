//! Shared wire conversion for language SDK setup APIs.

use std::path::PathBuf;

use serde::Deserialize;

use crate::{
    MicrosandboxError, MicrosandboxResult,
    config::{GlobalConfig, GlobalConfigPatch, PathsConfigPatch, layers::BackendConfig},
};

use super::{InstallOptions, InstallSource};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeConfigInput {
    home: Option<PathBuf>,
    msb_path: Option<PathBuf>,
    libkrunfw_path: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct InstallOptionsInput {
    source: Option<String>,
    source_path: Option<PathBuf>,
    version: Option<String>,
    force: bool,
    verify: Option<bool>,
    expected_archive_sha256: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeConfigInput {
    fn resolve(self, sources: BackendConfig) -> MicrosandboxResult<GlobalConfig> {
        let mut options = GlobalConfigPatch::new();
        let mut paths = PathsConfigPatch::new();
        if let Some(home) = self.home {
            options.home_mut(home);
        }
        if let Some(msb) = self.msb_path {
            paths.msb_mut(msb);
        }
        if let Some(library) = self.libkrunfw_path {
            paths.libkrunfw_mut(library);
        }
        let sources = sources.prepare_for_local_backend(options.paths(paths))?;
        Ok(sources.resolved_config().as_ref().clone())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve language SDK overrides with user settings, process paths, and managed policy.
#[doc(hidden)]
pub fn binding_runtime_config(json: &str) -> MicrosandboxResult<GlobalConfig> {
    let input: RuntimeConfigInput = serde_json::from_str(json)
        .map_err(|error| MicrosandboxError::Custom(format!("invalid runtime config: {error}")))?;
    input.resolve(BackendConfig::load()?)
}

/// Decode the common installation options without acquiring any artifacts.
#[doc(hidden)]
pub fn binding_install_options(json: &str) -> MicrosandboxResult<InstallOptions> {
    let input: InstallOptionsInput = serde_json::from_str(json)
        .map_err(|error| MicrosandboxError::Custom(format!("invalid install options: {error}")))?;
    let source = match (input.source.as_deref().unwrap_or("release_download"), input.source_path) {
        ("release_download", None) => InstallSource::ReleaseDownload,
        ("embedded_archive", None) => InstallSource::EmbeddedArchive,
        ("archive", Some(path)) => InstallSource::Archive(path),
        ("directory", Some(path)) => InstallSource::Directory(path),
        _ => return Err(MicrosandboxError::Custom(
            "source must be release_download or embedded_archive without source_path, or archive or directory with source_path".into(),
        )),
    };
    let defaults = InstallOptions::default();
    Ok(InstallOptions {
        source,
        version: input.version.unwrap_or(defaults.version),
        force: input.force,
        verify: input.verify.unwrap_or(defaults.verify),
        expected_archive_sha256: input.expected_archive_sha256,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_bindings_keep_process_paths_below_managed_policy() {
        let _guard = crate::test_support::lock_env();
        let previous = std::env::var_os("MSB_PATH");
        let _restore = scopeguard::guard(previous, |previous| unsafe {
            match previous {
                Some(value) => std::env::set_var("MSB_PATH", value),
                None => std::env::remove_var("MSB_PATH"),
            }
        });
        // SAFETY: environment-dependent tests hold the shared lock.
        unsafe { std::env::set_var("MSB_PATH", "/environment/msb") };
        for (managed, expected) in [
            (serde_json::json!({}), "/environment/msb"),
            (
                serde_json::json!({"paths":{"msb":"/managed/msb"}}),
                "/managed/msb",
            ),
        ] {
            let sources = BackendConfig::new(
                serde_json::from_value(serde_json::json!({"paths":{"msb":"/user/msb"}})).unwrap(),
                serde_json::from_value(managed).unwrap(),
            );
            let input: RuntimeConfigInput =
                serde_json::from_str(r#"{"msb_path":"/sdk/msb"}"#).unwrap();
            assert_eq!(
                input.resolve(sources).unwrap().paths.msb,
                Some(expected.into())
            );
        }
    }

    #[test]
    fn install_defaults_and_explicit_options_match_rust() {
        let defaults = binding_install_options("{}").unwrap();
        assert_eq!(defaults.source, InstallSource::ReleaseDownload);
        assert!(defaults.verify);
        assert!(!defaults.force);
        assert_eq!(defaults.version, InstallOptions::default().version);
        let options = binding_install_options(r#"{"source":"archive","source_path":"bundle.tar.gz","force":true,"verify":false,"version":"older","expected_archive_sha256":"digest"}"#).unwrap();
        assert_eq!(
            options.source,
            InstallSource::Archive("bundle.tar.gz".into())
        );
        assert!(options.force);
        assert!(!options.verify);
        assert_eq!(options.version, "older");
        assert_eq!(options.expected_archive_sha256.as_deref(), Some("digest"));
    }

    #[test]
    fn source_options_reject_ambiguous_or_unknown_acquisition() {
        for json in [
            r#"{"source":"directory"}"#,
            r#"{"source":"archive"}"#,
            r#"{"source":"release_download","source_path":"ignored"}"#,
            r#"{"source":"embedded_archive","source_path":"ignored"}"#,
            r#"{"source":"unknown"}"#,
            r#"{"typo":true}"#,
        ] {
            assert!(binding_install_options(json).is_err(), "{json}");
        }
        assert_eq!(
            binding_install_options(r#"{"source":"embedded_archive"}"#)
                .unwrap()
                .source,
            InstallSource::EmbeddedArchive
        );
    }
}
