//! Translate guarded raw local records without promoting serde defaults into source evidence.

use std::collections::BTreeMap;

use microsandbox_protocol::HANDOFF_INIT_AUTO;
use microsandbox_protocol::init_observation::InitObservation;
use microsandbox_runtime::retention::ScriptBackingEvidence;
use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureInit, RuntimeCaptureInput, RuntimeCaptureScript, RuntimeCaptureText,
    SavedHostname, SavedInitSelection, SavedOrigin, SavedRuntimeConfig, SavedScriptBacking,
    SavedScriptMetadata, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{SandboxRuntimeOptions, hostname_from_sandbox_name};
use serde_json::Value;

use crate::sandbox::init_provenance::InitProvenance;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-private source adapter. It cannot be serialized or formatted as diagnostics.
///
/// The caller must select the raw record, init observation and script evidence under one
/// capture/lifecycle guard. This validates their runtime consistency, not catalog identity,
/// generation, disk-cut coherence or full-state handle fidelity. No source paths are opened.
/// Keep the original evidence alive through publication and independently validate other fields.
pub struct RuntimeCaptureSource<'a> {
    pub(super) recorded: &'a Value,
    pub(super) config: SandboxConfig,
    init: Option<&'a InitObservation>,
    scripts: Option<&'a ScriptBackingEvidence>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> RuntimeCaptureSource<'a> {
    /// Decode a retained source with redacted diagnostics and reject contradictory hints.
    /// Missing historical distinctions remain unknown, never new declarations.
    pub fn from_recorded(
        recorded: &'a Value,
        init: Option<&'a InitObservation>,
        scripts: Option<&'a ScriptBackingEvidence>,
    ) -> MicrosandboxResult<Self> {
        let config: SandboxConfig = serde_json::from_value(recorded.clone())
            .map_err(|_| invalid("runtime", "invalid retained configuration"))?;
        if config.command_provenance.as_ref().is_some_and(|origin| {
            !origin.matches(&config.spec.runtime.cmd) || recorded.pointer("/runtime/cmd").is_none()
        }) {
            return Err(invalid(
                "runtime.cmd",
                "retained command evidence is inconsistent",
            ));
        }
        if config
            .environment_provenance
            .as_ref()
            .is_some_and(|origin| !origin.matches(&config.spec.env, config.spec.init.as_ref()))
        {
            return Err(invalid(
                "runtime.env",
                "retained environment evidence is inconsistent",
            ));
        }
        if config.init_provenance.as_ref().is_some_and(|origin| {
            !origin.matches(config.spec.init.as_ref()) || recorded.get("init").is_none()
        }) {
            return Err(invalid(
                "runtime.init",
                "retained init evidence is inconsistent",
            ));
        }
        if let Some(observation) = init {
            let recorded_init = recorded.get("init");
            let consistent = match observation {
                InitObservation::Builtin => recorded_init.is_none_or(Value::is_null),
                InitObservation::Handoff { path } => {
                    path.starts_with('/')
                        && path.len() <= 4096
                        && !path.contains('\0')
                        && recorded_init.is_none_or(|v| {
                            v.get("cmd")
                                .and_then(Value::as_str)
                                .is_some_and(|cmd| cmd == "auto" || cmd == path)
                        })
                }
            };
            if !consistent {
                return Err(invalid("runtime.init", "observed init is inconsistent"));
            }
        }
        if let Some(ScriptBackingEvidence::Observed { files, .. }) = scripts {
            let expected = recorded
                .pointer("/runtime/scripts")
                .and_then(Value::as_object);
            if !expected.map_or(files.is_empty(), |expected| {
                expected.len() == files.len() && files.keys().all(|key| expected.contains_key(key))
            }) {
                return Err(invalid(
                    "runtime.scripts",
                    "observed script inventory is inconsistent",
                ));
            }
        }
        Ok(Self {
            recorded,
            config,
            init,
            scripts,
        })
    }

    /// Retain guest ownership and directory metadata independently of reusable defaults.
    /// Only full capture needs this closure evidence; disk boot uses fresh runtime directories.
    pub(super) fn script_backing(
        &self,
        runtime: &SavedRuntimeConfig,
        full: bool,
    ) -> MicrosandboxResult<Option<SavedValue<SavedScriptBacking>>> {
        if !full {
            return Ok(None);
        }
        let Some(ScriptBackingEvidence::Observed {
            files,
            runtime_directory,
            scripts_directory,
        }) = self.scripts
        else {
            return Ok(unknown(SavedUnknownReason::NotObserved));
        };
        if self.recorded.pointer("/runtime/scripts").is_none() {
            return Ok(unknown(SavedUnknownReason::NotRecorded));
        }
        let backing = SavedScriptBacking {
            runtime_directory: SavedScriptMetadata {
                uid: runtime_directory.uid,
                gid: runtime_directory.gid,
                mode: runtime_directory.mode,
            },
            scripts_directory: SavedScriptMetadata {
                uid: scripts_directory.uid,
                gid: scripts_directory.gid,
                mode: scripts_directory.mode,
            },
            files: files
                .iter()
                .map(|(name, file)| {
                    (
                        name.clone(),
                        SavedScriptMetadata {
                            uid: file.uid,
                            gid: file.gid,
                            mode: file.mode,
                        },
                    )
                })
                .collect(),
        };
        backing
            .validate(runtime)
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
        Ok(Some(SavedValue::Value {
            value: backing,
            origin: SavedOrigin::Observed,
        }))
    }

    /// Assemble nonserializable runtime input for `project_runtime_capture`.
    ///
    /// Registered script bytes come only from guarded backing observations. Full-state
    /// directory metadata, handle closure and identity remain separate requirements; this
    /// input is not permission to resume. Pending records must not replace active evidence.
    pub fn input(&self) -> RuntimeCaptureInput<'_> {
        // Exhaustive destructuring requires an explicit policy for new runtime fields.
        // Logging/metrics are destination settings, never reusable source defaults.
        let SandboxRuntimeOptions {
            workdir,
            shell,
            scripts: _,
            entrypoint,
            cmd: _,
            hostname,
            user,
            log_level: _,
            metrics_sample_interval_ms: _,
            disable_metrics_sample: _,
            guest_clock,
        } = &self.config.spec.runtime;
        let cmd = if self.recorded.pointer("/runtime/cmd").is_none() {
            unknown(SavedUnknownReason::NotRecorded)
        } else if let Some(origin) = &self.config.command_provenance {
            configured(origin.defaults.as_ref().map(|args| literals(args)))
        } else {
            // Recorded runtime CMD can be a detached one-shot invocation. Its spelling
            // alone is not evidence of reusable defaults, even when it looks familiar.
            unknown(SavedUnknownReason::NotRecorded)
        };
        let env = if self.recorded.get("env").is_some() {
            configured(Some(
                self.config
                    .spec
                    .env
                    .iter()
                    .map(|entry| {
                        (
                            entry.key.as_str(),
                            self.environment_text(&entry.key, &entry.value, false),
                        )
                    })
                    .collect(),
            ))
        } else {
            unknown(SavedUnknownReason::NotRecorded)
        };
        let hostname = if self.recorded.pointer("/runtime/hostname").is_none() {
            unknown(SavedUnknownReason::NotRecorded)
        } else if let Some(name) = hostname {
            configured(Some(SavedHostname::Explicit {
                value: name.clone(),
            }))
        } else if self.recorded.get("name").is_some() {
            Some(SavedValue::Value {
                value: SavedHostname::Generated {
                    value: hostname_from_sandbox_name(&self.config.spec.name),
                },
                origin: SavedOrigin::Platform,
            })
        } else {
            unknown(SavedUnknownReason::NotRecorded)
        };
        RuntimeCaptureInput {
            workdir: self.recorded_option("/runtime/workdir", workdir.as_deref()),
            shell: self.recorded_option("/runtime/shell", shell.as_deref()),
            entrypoint: self.recorded_option(
                "/runtime/entrypoint",
                entrypoint.as_ref().map(|v| literals(v)),
            ),
            cmd,
            env,
            scripts: self.script_input(),
            init: self.init_input(),
            hostname,
            user: self.recorded_option("/runtime/user", user.as_deref()),
            guest_clock: self.recorded_option("/runtime/guest_clock", *guest_clock),
        }
    }

    /// Project only desired next-start runtime intent. Guest observations and materialized
    /// scripts are deliberately ignored. Missing private env/CMD provenance stays unknown
    /// or requires bindings, just as for active capture; pending is never a restore fallback.
    pub fn pending_input(&self) -> RuntimeCaptureInput<'_> {
        let mut input = self.input();
        input.init = match (&self.config.spec.init, &self.config.init_provenance) {
            (
                Some(init),
                Some(origin @ (InitProvenance::Auto { .. } | InitProvenance::Path { .. })),
            ) => {
                // Image resolution may have replaced `auto` with an executable path.
                // The validated, value-bound provenance preserves the requested choice.
                let cmd = if matches!(origin, InitProvenance::Auto { .. }) {
                    HANDOFF_INIT_AUTO
                } else {
                    &init.cmd
                };
                configured(Some(RuntimeCaptureInit::RequestedHandoff {
                    cmd,
                    args: literals(&init.args),
                    env: init
                        .env
                        .iter()
                        .map(|(key, value)| (key.as_str(), self.environment_text(key, value, true)))
                        .collect(),
                }))
            }
            // An explicitly recorded null has unambiguous no-handoff meaning even in
            // old records. A non-null resolved path alone cannot establish original intent.
            (None, _) => self.recorded_option("/init", None),
            _ => unknown(SavedUnknownReason::NotRecorded),
        };
        input.scripts = if self.recorded.pointer("/runtime/scripts").is_some() {
            configured(Some(
                self.config
                    .spec
                    .runtime
                    .scripts
                    .iter()
                    .map(|(name, content)| {
                        (name.as_str(), RuntimeCaptureScript::Declaration(content))
                    })
                    .collect(),
            ))
        } else {
            unknown(SavedUnknownReason::NotRecorded)
        };
        input
    }

    fn recorded_option<T>(&self, path: &str, value: Option<T>) -> Option<SavedValue<T>> {
        if self.recorded.pointer(path).is_some() {
            configured(value)
        } else {
            unknown(SavedUnknownReason::NotRecorded)
        }
    }

    fn environment_text<'b>(
        &self,
        key: &str,
        value: &'b str,
        init: bool,
    ) -> RuntimeCaptureText<'b> {
        let typed_secret = self
            .config
            .spec
            .network
            .secrets
            .as_ref()
            .is_some_and(|secrets| secrets.secrets.iter().any(|entry| entry.env_var == key));
        if !typed_secret
            && self
                .config
                .environment_provenance
                .as_ref()
                .is_some_and(|origin| origin.is_literal(key, value, init))
        {
            RuntimeCaptureText::Literal(value)
        } else {
            RuntimeCaptureText::BindingRequired
        }
    }

    fn init_input(&self) -> Option<SavedValue<RuntimeCaptureInit<'_>>> {
        let Some(observed) = self.init else {
            return unknown(SavedUnknownReason::NotObserved);
        };
        match observed {
            InitObservation::Builtin => Some(SavedValue::Value {
                value: RuntimeCaptureInit::Builtin,
                origin: SavedOrigin::Observed,
            }),
            InitObservation::Handoff { path } => {
                let Some(configured) = &self.config.spec.init else {
                    return unknown(SavedUnknownReason::NotRecorded);
                };
                let selection = match self.config.init_provenance {
                    Some(InitProvenance::Auto { .. }) => SavedInitSelection::Auto,
                    Some(InitProvenance::Path { .. }) => SavedInitSelection::Path,
                    _ => return unknown(SavedUnknownReason::NotRecorded),
                };
                Some(SavedValue::Value {
                    value: RuntimeCaptureInit::Handoff {
                        selection,
                        resolved_path: path,
                        args: literals(&configured.args),
                        env: configured
                            .env
                            .iter()
                            .map(|(key, value)| {
                                (key.as_str(), self.environment_text(key, value, true))
                            })
                            .collect(),
                    },
                    origin: SavedOrigin::Observed,
                })
            }
        }
    }

    fn script_input(&self) -> Option<SavedValue<BTreeMap<&str, RuntimeCaptureScript<'_>>>> {
        if self.recorded.pointer("/runtime/scripts").is_none() {
            return unknown(SavedUnknownReason::NotRecorded);
        }
        let Some(ScriptBackingEvidence::Observed { files, .. }) = self.scripts else {
            return unknown(SavedUnknownReason::NotObserved);
        };
        Some(SavedValue::Value {
            value: files
                .iter()
                .map(|(name, file)| {
                    (
                        name.as_str(),
                        RuntimeCaptureScript::Inline {
                            content: &file.content,
                            mode: file.mode,
                        },
                    )
                })
                .collect(),
            origin: SavedOrigin::Observed,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn literals(values: &[String]) -> Vec<RuntimeCaptureText<'_>> {
    values
        .iter()
        .map(|value| RuntimeCaptureText::Literal(value))
        .collect()
}

fn configured<T>(value: Option<T>) -> Option<SavedValue<T>> {
    Some(match value {
        Some(value) => SavedValue::Value {
            value,
            origin: SavedOrigin::Configured,
        },
        None => SavedValue::Default {},
    })
}

fn unknown<T>(reason: SavedUnknownReason) -> Option<SavedValue<T>> {
    Some(SavedValue::Unknown { reason })
}

fn invalid(field: &str, detail: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("SCFG_INTEGRITY: {field}: {detail}"))
}
