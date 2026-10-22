//! Portable command/init/script data. These types cannot contain raw host paths or secret objects.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::GuestClockPolicy;
use crate::error::SnapshotManifestResult;
use crate::validation::validate_hostname;

use super::validation::{
    MAX_GUEST_PATH_BYTES, MAX_NAME_BYTES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES,
    MAX_TEXT_BYTES, binding, count, decode, encoded_size, error, invalid,
};
use super::value::deserialize_present;
use super::{SavedOrigin, SavedText, SavedValue};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Reusable runtime settings, excluding invocation, host files, credentials and observability.
///
/// A missing field was omitted; a present null is invalid. Explicit defaults, unknown
/// observations and concrete empty values have distinct tagged representations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRuntimeConfig {
    /// Guest working directory for newly started commands.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub workdir: Option<SavedValue<String>>,
    /// Shell for newly started commands, not a command to execute during restore.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub shell: Option<SavedValue<String>>,
    /// Configured image entrypoint, never an ancestor's one-shot invocation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub entrypoint: Option<SavedValue<Vec<SavedText>>>,
    /// Configured command defaults for new commands.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub cmd: Option<SavedValue<Vec<SavedText>>>,
    /// Declared command environment with logical bindings for excluded required inputs.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub env: Option<SavedValue<BTreeMap<String, SavedText>>>,
    /// Exact normalized registered scripts; restore materializes them without executing them.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub scripts: Option<SavedValue<BTreeMap<String, SavedScript>>>,
    /// Active init selection, including the actual path chosen by auto discovery.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub init: Option<SavedValue<SavedInit>>,
    /// Active guest name and whether a new disk boot should regenerate it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub hostname: Option<SavedValue<SavedHostname>>,
    /// Default user for new commands; never changes credentials of captured processes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub user: Option<SavedValue<String>>,
    /// Clock policy, which must agree with the existing authoritative clock extension.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub guest_clock: Option<SavedValue<GuestClockPolicy>>,
}

/// Init evidence or pending intent; declaration-only variants cannot be active defaults.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedInit {
    /// The minimal microsandbox agent/init path, without a handoff executable.
    // Keep this a strict empty record; a tagged unit variant would ignore extras.
    Builtin {},
    /// Next-start intent only. This does not claim that discovery or handoff happened.
    RequestedHandoff {
        /// `auto` or an absolute guest executable, never a host lookup instruction.
        cmd: String,
        /// Declared supplemental arguments.
        args: Vec<SavedText>,
        /// Declared init environment, with excluded inputs represented by bindings.
        env: BTreeMap<String, SavedText>,
    },
    /// A resolved in-guest executable. Auto intent does not mean rediscover on restore.
    Handoff {
        /// Original discovery or explicit-path intent.
        selection: SavedInitSelection,
        /// Actual absolute guest executable used by this capture.
        resolved_path: String,
        /// Exact supplemental arguments, excluding implicit `argv[0]`.
        args: Vec<SavedText>,
        /// Additional init environment, separate from command defaults.
        env: BTreeMap<String, SavedText>,
    },
}

/// Original handoff selection, retained separately from the resolved executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedInitSelection {
    /// The source explicitly selected the recorded guest path.
    Path,
    /// The source used discovery; normal saved restore still uses the resolved path.
    Auto,
}

/// Guest-visible hostname, without transferring ownership of the source sandbox identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedHostname {
    /// The source chose a hostname explicitly; eligible for disk-boot fallback.
    Explicit {
        /// Validated guest hostname.
        value: String,
    },
    /// Generated source identity, regenerated on disk boot and preserved only by full state.
    Generated {
        /// Source guest hostname, for compatibility/provenance rather than new ownership.
        value: String,
    },
}

/// Registered script backing or a logical requirement for replacement content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedScript {
    /// Pending source declaration; no materialization, mode or backing digest is claimed.
    Declaration {
        /// Declared UTF-8 script, before the normal next-start registration process.
        content: String,
    },
    /// Exact normalized bytes, with no second wrapping or host-file read on restore.
    Inline {
        /// UTF-8 body from the registered/materialized script.
        content: String,
        /// Permission bits only, never setuid/setgid/sticky or a filesystem object type.
        mode: u16,
        /// Lowercase SHA-256 of the exact UTF-8 body, prefixed with `sha256:`.
        digest: String,
    },
    /// Capture excluded the body and retained a destination requirement instead.
    Binding {
        /// Logical binding, with no body/hash retained in this record.
        id: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedRuntimeConfig {
    /// Decode a bounded runtime section without leaking rejected values in diagnostics.
    ///
    /// This is not admission of the complete config extension: binding inventory,
    /// source generation, other policy families and descriptor projections also need validation.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "active.runtime")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate an active section before applying overrides, clearing fields or preparing input.
    /// Pending declarations must never be reinterpreted as observed execution/backing.
    pub fn validate_active(&self) -> SnapshotManifestResult<()> {
        self.validate_active_role()?;
        self.validate()
    }

    // Role admission must not serialize source values before capture exclusions. Keep this
    // separate so whole-document validation can also avoid validating the same section twice.
    pub(super) fn validate_active_role(&self) -> SnapshotManifestResult<()> {
        if matches!(
            self.init.as_ref().and_then(SavedValue::value),
            Some(SavedInit::RequestedHandoff { .. })
        ) {
            return invalid(
                "SCFG_IDENTITY",
                "active.runtime.init",
                "pending init declaration is not active evidence",
            );
        }
        if self
            .scripts
            .as_ref()
            .and_then(SavedValue::value)
            .is_some_and(|scripts| {
                scripts
                    .values()
                    .any(|script| matches!(script, SavedScript::Declaration { .. }))
            })
        {
            return invalid(
                "SCFG_IDENTITY",
                "active.runtime.scripts",
                "pending script declaration is not active backing",
            );
        }
        Ok(())
    }

    /// Validate active or pending syntax, bounds and references. Active consumers must also
    /// call `validate_active`; generic validation alone does not authorize use as defaults.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "active.runtime")?;
        for (field, saved) in [
            ("active.runtime.workdir", &self.workdir),
            ("active.runtime.shell", &self.shell),
        ] {
            if let Some(value) = saved.as_ref().and_then(SavedValue::value) {
                // Shell lookup and relative guest workdirs follow the existing command
                // contract. Only an observed init executable must be an absolute path.
                if value.is_empty() || value.len() > MAX_GUEST_PATH_BYTES || value.contains('\0') {
                    return invalid("SCFG_VALUE", field, "invalid guest command setting");
                }
            }
        }
        for (field, saved) in [
            ("active.runtime.entrypoint", &self.entrypoint),
            ("active.runtime.cmd", &self.cmd),
        ] {
            if let Some(values) = saved.as_ref().and_then(SavedValue::value) {
                texts(values, field)?;
            }
        }
        if let Some(values) = self.env.as_ref().and_then(SavedValue::value) {
            environment(values, "active.runtime.env")?;
        }
        if let Some(scripts) = self.scripts.as_ref().and_then(SavedValue::value) {
            count(scripts.len(), "active.runtime.scripts")?;
            let mut total = 0;
            for (name, script) in scripts {
                // Do not repair an unsafe name by discarding directories. Destination
                // materialization must additionally enforce its host's filename rules.
                if name.is_empty()
                    || name.len() > MAX_NAME_BYTES
                    || matches!(name.as_str(), "." | "..")
                    || name.contains(['\0', '/', '\\'])
                {
                    return invalid(
                        "SCFG_VALUE",
                        "active.runtime.scripts",
                        "script name must be one filename",
                    );
                }
                if let SavedScript::Inline { content, .. } | SavedScript::Declaration { content } =
                    script
                {
                    if content.len() > MAX_SAVED_SCRIPT_BYTES {
                        return invalid(
                            "SCFG_LIMIT",
                            "active.runtime.scripts",
                            "script payload is too large",
                        );
                    }
                    total += content.len();
                    if total > MAX_SAVED_SCRIPTS_BYTES {
                        return invalid(
                            "SCFG_LIMIT",
                            "active.runtime.scripts",
                            "combined script payload is too large",
                        );
                    }
                }
                match script {
                    SavedScript::Declaration { .. } => {
                        if !matches!(
                            self.scripts,
                            Some(SavedValue::Value {
                                origin: SavedOrigin::Configured,
                                ..
                            })
                        ) {
                            return invalid(
                                "SCFG_VALUE",
                                "active.runtime.scripts",
                                "script declaration requires configured origin",
                            );
                        }
                    }
                    SavedScript::Inline {
                        content,
                        mode,
                        digest,
                    } => {
                        if *mode > 0o777 {
                            return invalid(
                                "SCFG_VALUE",
                                "active.runtime.scripts",
                                "script mode contains unsupported bits",
                            );
                        }
                        let expected =
                            format!("sha256:{}", hex::encode(Sha256::digest(content.as_bytes())));
                        if *digest != expected {
                            return invalid(
                                "SCFG_INTEGRITY",
                                "active.runtime.scripts",
                                "inline script digest does not match its bytes",
                            );
                        }
                    }
                    SavedScript::Binding { id } => binding(id, "active.runtime.scripts")?,
                }
            }
        }
        match self.init.as_ref().and_then(SavedValue::value) {
            Some(SavedInit::Handoff {
                resolved_path,
                args,
                env,
                ..
            }) => {
                guest_path(resolved_path, "active.runtime.init.resolved_path")?;
                texts(args, "active.runtime.init.args")?;
                environment(env, "active.runtime.init.env")?;
            }
            Some(SavedInit::RequestedHandoff { cmd, args, env }) => {
                if !matches!(
                    self.init,
                    Some(SavedValue::Value {
                        origin: SavedOrigin::Configured,
                        ..
                    })
                ) {
                    return invalid(
                        "SCFG_VALUE",
                        "active.runtime.init",
                        "init declaration requires configured origin",
                    );
                }
                if cmd != "auto" {
                    guest_path(cmd, "active.runtime.init.cmd")?;
                }
                texts(args, "active.runtime.init.args")?;
                environment(env, "active.runtime.init.env")?;
            }
            Some(SavedInit::Builtin {}) | None => {}
        }
        if let Some(hostname) = self.hostname.as_ref().and_then(SavedValue::value) {
            let (SavedHostname::Explicit { value } | SavedHostname::Generated { value }) = hostname;
            if value.contains('\0') {
                return invalid(
                    "SCFG_VALUE",
                    "active.runtime.hostname",
                    "invalid guest hostname",
                );
            }
            validate_hostname(Some(value)).map_err(|_| {
                error(
                    "SCFG_VALUE",
                    "active.runtime.hostname",
                    "invalid guest hostname",
                )
            })?;
        }
        if let Some(user) = self.user.as_ref().and_then(SavedValue::value)
            && (user.is_empty() || user.len() > MAX_GUEST_PATH_BYTES || user.contains('\0'))
        {
            return invalid(
                "SCFG_VALUE",
                "active.runtime.user",
                "invalid default command user",
            );
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn text(value: &SavedText, field: &str) -> SnapshotManifestResult<()> {
    match value {
        SavedText::Literal { value } if value.len() > MAX_TEXT_BYTES || value.contains('\0') => {
            invalid(
                "SCFG_VALUE",
                field,
                "text exceeds its bound or contains a NUL byte",
            )
        }
        SavedText::Literal { .. } => Ok(()),
        SavedText::Binding { id } => binding(id, field),
    }
}

fn texts(values: &[SavedText], field: &str) -> SnapshotManifestResult<()> {
    count(values.len(), field)?;
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

fn environment(values: &BTreeMap<String, SavedText>, field: &str) -> SnapshotManifestResult<()> {
    count(values.len(), field)?;
    for (name, value) in values {
        if name.is_empty() || name.len() > MAX_NAME_BYTES || name.contains(['=', '\0']) {
            return invalid("SCFG_VALUE", field, "invalid environment variable name");
        }
        text(value, field)?;
    }
    Ok(())
}

fn guest_path(value: &str, field: &str) -> SnapshotManifestResult<()> {
    if !value.starts_with('/') || value.len() > MAX_GUEST_PATH_BYTES || value.contains('\0') {
        return invalid(
            "SCFG_VALUE",
            field,
            "expected a bounded absolute guest path",
        );
    }
    Ok(())
}
