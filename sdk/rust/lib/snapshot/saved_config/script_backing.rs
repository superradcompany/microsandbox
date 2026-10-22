//! Schema-bounded entry into the runtime-reusable filesystem capture primitive.

use std::{collections::BTreeSet, fs::File, path::Path};

use microsandbox_filesystem::{
    CapturedRuntimeScripts, RuntimeBootScript, RuntimeRestoredScript, RuntimeScriptLimits,
    RuntimeScriptMetadata, stage_runtime_boot_scripts, stage_runtime_restored_scripts,
};
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES, SavedOrigin,
    SavedValue,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{RuntimeConfigurationPlan, SavedConfigurationPlan};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedConfigurationPlan {
    /// Stage source-independent full-capture backing without admitting VM execution.
    /// Full filesystem/device restoration must still validate every captured handle and
    /// unregistered resource. Bound bodies lack retained identity and cannot use this proof.
    pub fn stage_full_scripts(&self, parent: &Path) -> MicrosandboxResult<TempDir> {
        let fail = || {
            MicrosandboxError::InvalidConfig("SCFG_IDENTITY: runtime.scripts: captured backing identity is unavailable or differs".into())
        };
        if !self.context().full_resume {
            return Err(fail());
        }
        let Some(SavedValue::Value {
            value: backing,
            origin: SavedOrigin::Observed,
        }) = &self.script_backing
        else {
            return Err(fail());
        };
        let Some(digests) = &self.script_digests else {
            return Err(fail());
        };
        self.runtime()
            .inputs()
            .scripts
            .require_available("runtime.scripts")?;
        let selected = self.runtime().scripts();
        if !selected.keys().eq(backing.files.keys()) || !selected.keys().eq(digests.keys()) {
            return Err(fail());
        }
        let mut inputs = Vec::with_capacity(selected.len());
        for (name, script) in selected {
            let metadata = backing.files[name];
            let (digest, mode) = &digests[name];
            if *mode != metadata.mode
                || script.mode != metadata.mode
                || format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(script.content.as_bytes()))
                ) != *digest
            {
                return Err(fail());
            }
            inputs.push(RuntimeRestoredScript {
                name,
                content: &script.content,
                metadata: RuntimeScriptMetadata {
                    uid: metadata.uid,
                    gid: metadata.gid,
                    mode: metadata.mode,
                },
            });
        }
        let directory = |v: microsandbox_types::snapshot::saved_config::SavedScriptMetadata| {
            RuntimeScriptMetadata {
                uid: v.uid,
                gid: v.gid,
                mode: v.mode,
            }
        };
        stage_runtime_restored_scripts(
            parent,
            &inputs,
            directory(backing.runtime_directory),
            directory(backing.scripts_directory),
            script_limits(),
        )
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
    }
}

impl RuntimeConfigurationPlan {
    /// Stage exact selected script bytes for a new boot, without consulting the source.
    ///
    /// This is private preparation only. The caller owns cleanup until adoption and must
    /// still complete destination policy and activation checks. Full-resume plans refuse:
    /// matching bytes/modes cannot prove compatibility with captured open file handles.
    pub fn stage_disk_scripts(&self, parent: &Path) -> MicrosandboxResult<TempDir> {
        if self.inputs().requires_full_identity {
            return Err(MicrosandboxError::InvalidConfig(
                "SCFG_IDENTITY: runtime.scripts: full resume requires captured backing".into(),
            ));
        }
        self.inputs().scripts.require_available("runtime.scripts")?;
        let scripts: Vec<_> = self
            .scripts()
            .iter()
            .map(|(name, script)| RuntimeBootScript {
                name,
                content: &script.content,
                mode: script.mode,
            })
            .collect();
        stage_runtime_boot_scripts(parent, &scripts, script_limits())
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Capture local observations under an independently held source mutation/capture guard.
/// Nothing is exported or admitted here; sanitization and full-state closure checks remain required.
pub fn capture_runtime_scripts(
    runtime: &File,
    registered: &BTreeSet<String>,
) -> MicrosandboxResult<CapturedRuntimeScripts> {
    CapturedRuntimeScripts::capture(runtime, registered, script_limits())
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
}

fn script_limits() -> RuntimeScriptLimits {
    RuntimeScriptLimits {
        max_entries: MAX_SAVED_CONFIG_ENTRIES,
        max_script_bytes: MAX_SAVED_SCRIPT_BYTES,
        max_total_bytes: MAX_SAVED_SCRIPTS_BYTES,
    }
}
