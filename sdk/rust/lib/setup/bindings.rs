//! Shared wire conversion for language SDK setup APIs.

use std::path::PathBuf;

use serde::Deserialize;

use crate::{MicrosandboxError, MicrosandboxResult, config::GlobalConfig};

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
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode language SDK overrides on top of the persisted global configuration.
#[doc(hidden)]
pub fn binding_runtime_config(json: &str) -> MicrosandboxResult<GlobalConfig> {
    let input: RuntimeConfigInput = serde_json::from_str(json)
        .map_err(|error| MicrosandboxError::Custom(format!("invalid runtime config: {error}")))?;
    let mut config = crate::config::load_persisted_config_or_default()?;
    if let Some(home) = input.home {
        config.home = Some(home);
    }
    if let Some(msb) = input.msb_path {
        config.paths.msb = Some(msb);
    }
    if let Some(library) = input.libkrunfw_path {
        config.paths.libkrunfw = Some(library);
    }
    Ok(config)
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
