//! Source-side runtime projection: exclusions run before any portable text is constructed.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::{GuestClockPolicy, SnapshotManifestResult};

use super::capture_controls::validate_controls;
use super::validation::{count, invalid};
use super::{
    RuntimeCaptureAction, RuntimeCaptureTarget, SavedBindingKind, SavedHostname, SavedInit,
    SavedInitSelection, SavedRuntimeConfig, SavedScript, SavedText, SavedValue,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Capture-side text classification, established from guarded source evidence.
/// No Serialize/Debug implementation: this is not portable configuration.
#[derive(Clone, Copy)]
pub enum RuntimeCaptureText<'a> {
    /// Ordinary declared text. Caller controls may still exclude or bind it.
    Literal(&'a str),
    /// Host-derived, secret-typed or insufficiently classified text. Its bytes are not needed.
    BindingRequired,
}

/// Source script backing, already observed and normalized under the capture guard.
/// This deliberately has no serialization or host pathname.
pub enum RuntimeCaptureScript<'a> {
    /// Pending declaration, not materialized or normalized backing.
    Declaration(&'a str),
    /// Ordinary registered backing; exclusions apply before copying or hashing its body.
    Inline {
        /// Exact normalized UTF-8 backing, without rewrapping or execution.
        content: &'a str,
        /// Captured ordinary guest permission bits.
        mode: u16,
    },
    /// Excluded or unclassified backing whose bytes must not enter metadata.
    BindingRequired,
}

/// Guarded init evidence, separate from a portable init value.
pub enum RuntimeCaptureInit<'a> {
    /// Confirmed builtin init, not a substitute for missing historical evidence.
    Builtin,
    /// Next-start declaration; accepted only in pending input.
    RequestedHandoff {
        /// `auto` or an absolute guest path.
        cmd: &'a str,
        /// Declared supplemental arguments.
        args: Vec<RuntimeCaptureText<'a>>,
        /// Classified init-only environment.
        env: BTreeMap<&'a str, RuntimeCaptureText<'a>>,
    },
    /// Confirmed executable and configured supplemental inputs.
    Handoff {
        /// Original explicit path or auto-discovery intent.
        selection: SavedInitSelection,
        /// Guest-observed executable path; never a host path.
        resolved_path: &'a str,
        /// Supplemental argv, excluding one-shot invocation arguments.
        args: Vec<RuntimeCaptureText<'a>>,
        /// Classified init-only environment, including any inherited workload values.
        env: BTreeMap<&'a str, RuntimeCaptureText<'a>>,
    },
}

/// Nonserializable input assembled from one coherent active or pending source.
///
/// Callers must preserve raw field absence and unknown evidence, validate private origin
/// hints, and distinguish reusable command defaults from invocation. This type cannot prove
/// those facts or full-state backing fidelity. It performs no source lookup or inference.
#[derive(Default)]
pub struct RuntimeCaptureInput<'a> {
    /// Guest working directory.
    pub workdir: Option<SavedValue<&'a str>>,
    /// Guest shell.
    pub shell: Option<SavedValue<&'a str>>,
    /// Reusable configured entrypoint, not a resolved one-shot command.
    pub entrypoint: Option<SavedValue<Vec<RuntimeCaptureText<'a>>>>,
    /// Reusable configured command defaults.
    pub cmd: Option<SavedValue<Vec<RuntimeCaptureText<'a>>>>,
    /// Effective keyed command environment; callers resolve duplicate declarations first.
    pub env: Option<SavedValue<BTreeMap<&'a str, RuntimeCaptureText<'a>>>>,
    /// Exact registered script backing or explicit unknown evidence.
    pub scripts: Option<SavedValue<BTreeMap<&'a str, RuntimeCaptureScript<'a>>>>,
    /// Confirmed init selection and classified inputs.
    pub init: Option<SavedValue<RuntimeCaptureInit<'a>>>,
    /// Configured hostname and generated/explicit origin.
    pub hostname: Option<SavedValue<SavedHostname>>,
    /// Default user for future commands.
    pub user: Option<SavedValue<&'a str>>,
    /// Existing authoritative guest-clock policy.
    pub guest_clock: Option<SavedValue<GuestClockPolicy>>,
}

/// Sanitized runtime sections and the exact text binding inventory they use.
/// Other config families and descriptor consistency must still pass document validation.
pub struct RuntimeCaptureProjection {
    /// Active settings, without fallback from pending intent.
    pub active: SavedRuntimeConfig,
    /// Sanitized next-start intent, never automatic restore defaults.
    pub pending: Option<SavedRuntimeConfig>,
    /// Logical text requirements only; never resolved values or host lookup instructions.
    pub bindings: BTreeMap<String, SavedBindingKind>,
}

struct Projector<'a> {
    controls: &'a BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    seen: BTreeSet<RuntimeCaptureTarget>,
    bindings: BTreeMap<String, SavedBindingKind>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Projector<'_> {
    fn runtime(
        &mut self,
        input: RuntimeCaptureInput<'_>,
        full: bool,
    ) -> SnapshotManifestResult<SavedRuntimeConfig> {
        use RuntimeCaptureTarget as T;
        let result = SavedRuntimeConfig {
            workdir: self.field(T::Workdir, input.workdir, full, |_, v| Ok(v.to_owned()))?,
            shell: self.field(T::Shell, input.shell, full, |_, v| Ok(v.to_owned()))?,
            entrypoint: self.field(T::Entrypoint, input.entrypoint, full, |p, v| {
                p.arguments(v, T::EntrypointArg)
            })?,
            cmd: self.field(T::Cmd, input.cmd, full, |p, v| p.arguments(v, T::CmdArg))?,
            env: self.field(T::Env, input.env, full, |p, v| p.environment(v, false))?,
            scripts: self.field(T::Scripts, input.scripts, full, |p, v| p.scripts(v, full))?,
            init: self.field(T::Init, input.init, full, |p, v| match v {
                RuntimeCaptureInit::Builtin => Ok(SavedInit::Builtin {}),
                RuntimeCaptureInit::RequestedHandoff { cmd, args, env } => {
                    Ok(SavedInit::RequestedHandoff {
                        cmd: cmd.to_owned(),
                        args: p.arguments(args, T::InitArg)?,
                        env: p.environment(env, true)?,
                    })
                }
                RuntimeCaptureInit::Handoff {
                    selection,
                    resolved_path,
                    args,
                    env,
                } => Ok(SavedInit::Handoff {
                    selection,
                    resolved_path: resolved_path.to_owned(),
                    args: p.arguments(args, T::InitArg)?,
                    env: p.environment(env, true)?,
                }),
            })?,
            hostname: self.field(T::Hostname, input.hostname, full, |_, v| Ok(v))?,
            user: self.field(T::User, input.user, full, |_, v| Ok(v.to_owned()))?,
            guest_clock: self.field(T::GuestClock, input.guest_clock, full, |_, v| Ok(v))?,
        };
        result.validate()?;
        Ok(result)
    }

    fn field<T, U>(
        &mut self,
        target: RuntimeCaptureTarget,
        input: Option<SavedValue<T>>,
        full: bool,
        project: impl FnOnce(&mut Self, T) -> SnapshotManifestResult<U>,
    ) -> SnapshotManifestResult<Option<SavedValue<U>>> {
        let Some(input) = input else { return Ok(None) };
        self.seen.insert(target.clone());
        if matches!(self.controls.get(&target), Some(RuntimeCaptureAction::Omit)) {
            if full
                && matches!(
                    target,
                    RuntimeCaptureTarget::Scripts
                        | RuntimeCaptureTarget::Init
                        | RuntimeCaptureTarget::Hostname
                        | RuntimeCaptureTarget::GuestClock
                )
            {
                return invalid(
                    "SCFG_IDENTITY",
                    target.field(),
                    "full-state capture cannot omit required state",
                );
            }
            // Do not visit children: excluded bytes must never be copied, hashed or serialized.
            return Ok(None);
        }
        Ok(Some(match input {
            SavedValue::Default {} => SavedValue::Default {},
            SavedValue::Unknown { reason } => SavedValue::Unknown { reason },
            SavedValue::Value { value, origin } => SavedValue::Value {
                value: project(self, value)?,
                origin,
            },
        }))
    }

    fn text(
        &mut self,
        target: RuntimeCaptureTarget,
        source: RuntimeCaptureText<'_>,
    ) -> SnapshotManifestResult<SavedText> {
        self.seen.insert(target.clone());
        if let Some(RuntimeCaptureAction::Bind(id)) = self.controls.get(&target) {
            self.bindings.insert(id.clone(), SavedBindingKind::Text);
            return Ok(SavedText::Binding { id: id.clone() });
        }
        match source {
            RuntimeCaptureText::Literal(value) => Ok(SavedText::Literal {
                value: value.to_owned(),
            }),
            RuntimeCaptureText::BindingRequired => invalid(
                "SCFG_BINDING",
                target.field(),
                "source text requires an explicit destination binding or permitted omission",
            ),
        }
    }

    fn arguments(
        &mut self,
        values: Vec<RuntimeCaptureText<'_>>,
        target: impl Fn(usize) -> RuntimeCaptureTarget,
    ) -> SnapshotManifestResult<Vec<SavedText>> {
        count(values.len(), target(0).field())?;
        values
            .into_iter()
            .enumerate()
            .map(|(i, value)| self.text(target(i), value))
            .collect()
    }

    fn environment(
        &mut self,
        values: BTreeMap<&str, RuntimeCaptureText<'_>>,
        init: bool,
    ) -> SnapshotManifestResult<BTreeMap<String, SavedText>> {
        count(
            values.len(),
            if init { "runtime.init" } else { "runtime.env" },
        )?;
        let mut result = BTreeMap::new();
        for (key, value) in values {
            let target = if init {
                RuntimeCaptureTarget::InitEnvKey(key.into())
            } else {
                RuntimeCaptureTarget::EnvKey(key.into())
            };
            self.seen.insert(target.clone());
            if matches!(self.controls.get(&target), Some(RuntimeCaptureAction::Omit)) {
                continue;
            }
            result.insert(key.to_owned(), self.text(target, value)?);
        }
        Ok(result)
    }

    fn scripts(
        &mut self,
        values: BTreeMap<&str, RuntimeCaptureScript<'_>>,
        full: bool,
    ) -> SnapshotManifestResult<BTreeMap<String, SavedScript>> {
        count(values.len(), "runtime.scripts")?;
        let mut result = BTreeMap::new();
        for (key, value) in values {
            let target = RuntimeCaptureTarget::ScriptKey(key.into());
            self.seen.insert(target.clone());
            let script = match self.controls.get(&target) {
                Some(RuntimeCaptureAction::Omit) if full => {
                    return invalid(
                        "SCFG_IDENTITY",
                        target.field(),
                        "full-state capture cannot omit required script backing",
                    );
                }
                Some(RuntimeCaptureAction::Omit) => continue,
                Some(RuntimeCaptureAction::Bind(id)) => {
                    self.bindings.insert(id.clone(), SavedBindingKind::Text);
                    SavedScript::Binding { id: id.clone() }
                }
                None => match value {
                    RuntimeCaptureScript::Declaration(content) => SavedScript::Declaration {
                        content: content.to_owned(),
                    },
                    RuntimeCaptureScript::Inline { content, mode } => SavedScript::Inline {
                        content: content.to_owned(),
                        mode,
                        digest: format!(
                            "sha256:{}",
                            hex::encode(Sha256::digest(content.as_bytes()))
                        ),
                    },
                    RuntimeCaptureScript::BindingRequired => {
                        return invalid(
                            "SCFG_BINDING",
                            target.field(),
                            "source script requires an explicit destination binding or permitted omission",
                        );
                    }
                },
            };
            result.insert(key.to_owned(), script);
        }
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Project guarded source input after applying caller-selected exclusions to both sections.
///
/// Known host-derived/secret/unknown text must use `BindingRequired`, which carries no bytes.
/// Ordinary literals are copied only after their exclusion has been checked. Controls must
/// match active or pending source input; pending-only controls do not invent active values.
/// Full-state preservation applies only to active state. This is not VM admission or complete
/// document validation, and it does not advertise saved-config extension support.
pub fn project_runtime_capture(
    active: RuntimeCaptureInput<'_>,
    pending: Option<RuntimeCaptureInput<'_>>,
    controls: &BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    full_state: bool,
) -> SnapshotManifestResult<RuntimeCaptureProjection> {
    // Reject the wrong evidence role before controls can hide it. No source text is copied.
    if matches!(
        active.init.as_ref().and_then(SavedValue::value),
        Some(RuntimeCaptureInit::RequestedHandoff { .. })
    ) || active
        .scripts
        .as_ref()
        .and_then(SavedValue::value)
        .is_some_and(|scripts| {
            scripts
                .values()
                .any(|script| matches!(script, RuntimeCaptureScript::Declaration(_)))
        })
    {
        return invalid(
            "SCFG_IDENTITY",
            "active.runtime",
            "pending declarations cannot provide active evidence",
        );
    }
    validate_controls(controls)?;
    // Pending selectors share the match set with active input. An unknown active
    // inventory must not let a pending-only match authorize losing full-state backing.
    if full_state
        && matches!(
            active.scripts,
            Some(SavedValue::Unknown { .. } | SavedValue::Default {})
        )
        && controls.iter().any(|(target, action)| {
            matches!(target, RuntimeCaptureTarget::ScriptKey(_))
                && matches!(action, RuntimeCaptureAction::Omit)
        })
    {
        return invalid(
            "SCFG_IDENTITY",
            "runtime.scripts",
            "full-state capture cannot omit script backing from an unknown inventory",
        );
    }
    let mut projector = Projector {
        controls,
        seen: BTreeSet::new(),
        bindings: BTreeMap::new(),
    };
    let active = projector.runtime(active, full_state)?;
    active.validate_active_role()?;
    let pending = pending
        .map(|input| projector.runtime(input, false))
        .transpose()?;
    for target in controls.keys() {
        if !projector.seen.contains(target) {
            return invalid(
                "SCFG_VALUE",
                target.field(),
                "capture selector did not match recorded input",
            );
        }
    }
    Ok(RuntimeCaptureProjection {
        active,
        pending,
        bindings: projector.bindings,
    })
}
