//! Context identity and secret-safe selection diagnostics.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Which context variant a [`super::Context`] implementation represents. Returned by
/// [`super::Context::kind`] for runtime introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextKind {
    /// Local libkrun + agentd backend. Spawns microVMs on the calling host.
    Local,
    /// Remote provider implementing the Microsandbox HTTP API.
    #[serde(alias = "cloud")]
    Remote,
}

/// How the active backend was selected.
///
/// This describes the selector, never its credential value. Context
/// diagnostics therefore cannot expose `MSB_API_KEY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextSelectionSource {
    /// Installed directly through an SDK constructor or setter.
    #[serde(rename = "programmatic")]
    Programmatic,
    /// Selected by managed configuration, ahead of environment and user preferences.
    #[serde(rename = "managed")]
    Managed,
    /// Selected explicitly by `MSB_BACKEND`.
    #[serde(rename = "MSB_BACKEND")]
    MsbBackend,
    /// Legacy diagnostic value. API credentials no longer select a backend.
    #[serde(rename = "MSB_API_KEY")]
    MsbApiKey,
    /// Selected by the profile named in `MSB_PROFILE`.
    #[serde(rename = "MSB_PROFILE")]
    MsbProfile,
    /// Selected by an explicit SDK profile constructor.
    #[serde(rename = "profile")]
    Profile,
    /// Selected by `active_profile` in the SDK config file.
    #[serde(rename = "active_profile")]
    ActiveProfile,
    /// Selected by the SDK's final local fallback.
    #[serde(rename = "default")]
    Default,
}

/// Secret-safe description of an SDK backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextInfo {
    /// Local or remote execution.
    pub kind: ContextKind,
    /// Effective cloud API endpoint. Absent for local backends.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Selector that chose this backend.
    pub source: ContextSelectionSource,
    /// Selected SDK profile, when profile-based selection was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ContextKind {
    pub(crate) fn is_available(self) -> bool {
        match self {
            Self::Local => cfg!(feature = "local"),
            Self::Remote => cfg!(feature = "cloud"),
        }
    }

    pub(crate) fn require_available(self) -> crate::MicrosandboxResult<()> {
        if self.is_available() {
            Ok(())
        } else {
            Err(crate::config::backend::feature_disabled(self.as_str()))
        }
    }

    /// Canonical spelling for configuration and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

impl ContextSelectionSource {
    /// Stable public name for this selection source.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Programmatic => "programmatic",
            Self::Managed => "managed",
            Self::MsbBackend => "MSB_BACKEND",
            Self::MsbApiKey => "MSB_API_KEY",
            Self::MsbProfile => "MSB_PROFILE",
            Self::Profile => "profile",
            Self::ActiveProfile => "active_profile",
            Self::Default => "default",
        }
    }
}
