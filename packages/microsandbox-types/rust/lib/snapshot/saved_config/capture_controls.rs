//! Capture-only runtime exclusions. Never use this to repair or admit an imported artifact.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::SnapshotManifestResult;

use super::inventory::merge_binding_uses;
use super::validation::{binding, count, invalid};
use super::{
    SavedBindingKind, SavedInit, SavedRuntimeConfig, SavedSandboxConfig, SavedScript, SavedText,
    SavedValue, collect_binding_uses,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Structural capture selectors. Keys containing dots are literal keys, not paths.
/// These controls are supplied by the capturing caller, never by snapshot metadata.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeCaptureTarget {
    /// Optional guest working directory.
    Workdir,
    /// Optional shell.
    Shell,
    /// Complete configured entrypoint.
    Entrypoint,
    /// One entrypoint argument; binding substitution preserves its position.
    EntrypointArg(usize),
    /// Complete configured command defaults, excluding one-shot invocation state.
    Cmd,
    /// One configured command argument.
    CmdArg(usize),
    /// Complete optional new-command environment.
    Env,
    /// One exact new-command environment key.
    EnvKey(String),
    /// Complete registered-script defaults; cannot be omitted from full-state capture.
    Scripts,
    /// One exact script name.
    ScriptKey(String),
    /// Complete init defaults; cannot be omitted from full-state capture.
    Init,
    /// One supplemental init argument.
    InitArg(usize),
    /// One exact init environment key.
    InitEnvKey(String),
    /// Guest hostname defaults; full-state identity cannot be omitted.
    Hostname,
    /// Default user for new commands.
    User,
    /// Guest clock policy; full-state policy cannot be omitted.
    GuestClock,
}

/// Exclusion is either omission of an optional default or an explicit destination requirement.
#[derive(Clone)]
pub enum RuntimeCaptureAction {
    /// Remove an optional field/key. Never remove a positional argument or required full backing.
    Omit,
    /// Replace text/script content with a logical text binding; no source bytes or digest remain.
    Bind(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureTarget {
    pub(super) fn field(&self) -> &'static str {
        match self {
            Self::Workdir => "runtime.workdir",
            Self::Shell => "runtime.shell",
            Self::Entrypoint | Self::EntrypointArg(_) => "runtime.entrypoint",
            Self::Cmd | Self::CmdArg(_) => "runtime.cmd",
            Self::Env | Self::EnvKey(_) => "runtime.env",
            Self::Scripts | Self::ScriptKey(_) => "runtime.scripts",
            Self::Init | Self::InitArg(_) | Self::InitEnvKey(_) => "runtime.init",
            Self::Hostname => "runtime.hostname",
            Self::User => "runtime.user",
            Self::GuestClock => "runtime.guest_clock",
        }
    }

    pub(super) fn whole_field(&self) -> bool {
        !matches!(
            self,
            Self::EntrypointArg(_)
                | Self::CmdArg(_)
                | Self::EnvKey(_)
                | Self::ScriptKey(_)
                | Self::InitArg(_)
                | Self::InitEnvKey(_)
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for RuntimeCaptureTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even caller-supplied map keys need not be appropriate for diagnostics.
        f.write_str(self.field())
    }
}

impl fmt::Debug for RuntimeCaptureAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Omit => "Omit",
            Self::Bind(_) => "Bind(..)",
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply caller exclusions to both active and pending local projection before any serialization.
///
/// This consumes a capture draft, not an imported artifact. Known secret/resource fields must
/// already have been projected to bindings, and source identity/backing must be independently
/// established. No source lookup, secret discovery, activation or extension emission occurs here.
/// Omission never shifts argv, removes individual init environment inputs, or discards full-state
/// script backing. Removing the complete optional init default is allowed only for disk capture.
/// Whole-field/key overlaps reject instead of depending on action order. The final document is
/// validated, including all remaining bindings and bounds; unrelated invalid metadata is not fixed.
pub fn apply_runtime_capture_controls(
    mut draft: SavedSandboxConfig,
    controls: &BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    full_state: bool,
) -> SnapshotManifestResult<SavedSandboxConfig> {
    draft.active.runtime.validate_active_role()?;
    validate_controls(controls)?;
    let mut removed_candidates = runtime_binding_ids(&draft.active.runtime);
    if let Some(pending) = &draft.pending {
        removed_candidates.extend(runtime_binding_ids(&pending.runtime));
    }
    for (target, action) in controls {
        if let RuntimeCaptureAction::Bind(id) = action {
            if draft
                .bindings
                .get(id)
                .is_some_and(|kind| *kind != SavedBindingKind::Text)
            {
                return invalid(
                    "SCFG_BINDING",
                    target.field(),
                    "capture binding has an incompatible value shape",
                );
            }
            draft.bindings.insert(id.clone(), SavedBindingKind::Text);
        }
        let active = apply_one(&mut draft.active.runtime, target, action, full_state)?;
        // Always sanitize pending too: it is exported metadata even though it is never a fallback.
        let pending = match &mut draft.pending {
            Some(pending) => apply_one(&mut pending.runtime, target, action, false)?,
            None => false,
        };
        if !active && !pending {
            return invalid(
                "SCFG_VALUE",
                target.field(),
                "capture selector did not match recorded input",
            );
        }
    }
    let mut uses = collect_binding_uses(&draft.active.runtime, &draft.active.network)?;
    merge_binding_uses(&mut uses, draft.active.storage.binding_uses()?)?;
    if let Some(pending) = &draft.pending {
        merge_binding_uses(
            &mut uses,
            collect_binding_uses(&pending.runtime, &pending.network)?,
        )?;
        merge_binding_uses(&mut uses, pending.storage.binding_uses()?)?;
    }
    // Remove only declarations displaced by these controls. Preserve shared consumers and
    // leave unrelated unused/mistyped declarations for strict document validation to reject.
    draft
        .bindings
        .retain(|id, _| !removed_candidates.contains(id) || uses.contains_key(id));
    draft.validate()?;
    Ok(draft)
}

fn apply_one(
    runtime: &mut SavedRuntimeConfig,
    target: &RuntimeCaptureTarget,
    action: &RuntimeCaptureAction,
    full: bool,
) -> SnapshotManifestResult<bool> {
    use RuntimeCaptureTarget as T;
    if matches!(action, RuntimeCaptureAction::Omit) {
        // Only captured active state requires full-state preservation. A selector
        // absent here may still match pending metadata, which is not running state.
        let required_active_state = match target {
            T::Scripts => runtime.scripts.is_some(),
            T::ScriptKey(key) => match &runtime.scripts {
                Some(SavedValue::Value { value, .. }) => value.contains_key(key),
                None => false,
                // Unknown/bound inventory is not proof that a script is absent.
                Some(_) => true,
            },
            T::Init => runtime.init.is_some(),
            T::Hostname => runtime.hostname.is_some(),
            T::GuestClock => runtime.guest_clock.is_some(),
            _ => false,
        };
        if full && required_active_state {
            return invalid(
                "SCFG_IDENTITY",
                target.field(),
                "full-state capture cannot omit required state; bind excluded script content instead",
            );
        }
        let found = match target {
            T::Workdir => runtime.workdir.take().is_some(),
            T::Shell => runtime.shell.take().is_some(),
            T::Entrypoint => runtime.entrypoint.take().is_some(),
            T::Cmd => runtime.cmd.take().is_some(),
            T::Env => runtime.env.take().is_some(),
            T::Scripts => runtime.scripts.take().is_some(),
            T::Init => runtime.init.take().is_some(),
            T::Hostname => runtime.hostname.take().is_some(),
            T::User => runtime.user.take().is_some(),
            T::GuestClock => runtime.guest_clock.take().is_some(),
            T::EnvKey(key) => {
                concrete(&mut runtime.env).is_some_and(|map| map.remove(key).is_some())
            }
            T::ScriptKey(key) => {
                concrete(&mut runtime.scripts).is_some_and(|map| map.remove(key).is_some())
            }
            T::EntrypointArg(_) | T::CmdArg(_) | T::InitArg(_) | T::InitEnvKey(_) => {
                return invalid(
                    "SCFG_BINDING",
                    target.field(),
                    "excluded positional or init input needs a binding",
                );
            }
        };
        return Ok(found);
    }
    let RuntimeCaptureAction::Bind(id) = action else {
        unreachable!()
    };
    if let T::ScriptKey(key) = target {
        let Some(script) = concrete(&mut runtime.scripts).and_then(|map| map.get_mut(key)) else {
            return Ok(false);
        };
        // Replacing the entire variant also removes the original body, mode and digest.
        *script = SavedScript::Binding { id: id.clone() };
        return Ok(true);
    }
    let value = match target {
        T::EntrypointArg(index) => {
            concrete(&mut runtime.entrypoint).and_then(|v| v.get_mut(*index))
        }
        T::CmdArg(index) => concrete(&mut runtime.cmd).and_then(|v| v.get_mut(*index)),
        T::EnvKey(key) => concrete(&mut runtime.env).and_then(|v| v.get_mut(key)),
        T::InitArg(index) => match concrete(&mut runtime.init) {
            Some(SavedInit::Handoff { args, .. } | SavedInit::RequestedHandoff { args, .. }) => {
                args.get_mut(*index)
            }
            _ => None,
        },
        T::InitEnvKey(key) => match concrete(&mut runtime.init) {
            Some(SavedInit::Handoff { env, .. } | SavedInit::RequestedHandoff { env, .. }) => {
                env.get_mut(key)
            }
            _ => None,
        },
        _ => {
            return invalid(
                "SCFG_BINDING",
                target.field(),
                "capture binding requires an individual text or script selector",
            );
        }
    };
    let Some(value) = value else {
        return Ok(false);
    };
    *value = SavedText::Binding { id: id.clone() };
    Ok(true)
}

fn concrete<T>(value: &mut Option<SavedValue<T>>) -> Option<&mut T> {
    match value {
        Some(SavedValue::Value { value, .. }) => Some(value),
        _ => None,
    }
}

/// Read references without validation/serialization: exclusions must run before content is encoded.
fn runtime_binding_ids(runtime: &SavedRuntimeConfig) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut record = |text: &SavedText| {
        if let SavedText::Binding { id } = text {
            ids.insert(id.clone());
        }
    };
    for list in [&runtime.entrypoint, &runtime.cmd]
        .into_iter()
        .flatten()
        .filter_map(SavedValue::value)
    {
        for text in list {
            record(text);
        }
    }
    if let Some(env) = runtime.env.as_ref().and_then(SavedValue::value) {
        for text in env.values() {
            record(text);
        }
    }
    if let Some(
        SavedInit::Handoff { args, env, .. } | SavedInit::RequestedHandoff { args, env, .. },
    ) = runtime.init.as_ref().and_then(SavedValue::value)
    {
        for text in args.iter().chain(env.values()) {
            record(text);
        }
    }
    if let Some(scripts) = runtime.scripts.as_ref().and_then(SavedValue::value) {
        for script in scripts.values() {
            if let SavedScript::Binding { id } = script {
                ids.insert(id.clone());
            }
        }
    }
    ids
}

pub(super) fn validate_controls(
    controls: &BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
) -> SnapshotManifestResult<()> {
    use RuntimeCaptureTarget as T;
    count(controls.len(), "capture.runtime")?;
    for (target, action) in controls {
        if controls.keys().any(|other| {
            other != target
                && other.field() == target.field()
                && (other.whole_field() || target.whole_field())
        }) {
            return invalid("SCFG_VALUE", target.field(), "overlapping capture controls");
        }
        match action {
            RuntimeCaptureAction::Bind(id) => {
                binding(id, target.field())?;
                if target.whole_field() {
                    return invalid(
                        "SCFG_BINDING",
                        target.field(),
                        "capture binding requires an individual text or script selector",
                    );
                }
            }
            RuntimeCaptureAction::Omit
                if matches!(
                    target,
                    T::EntrypointArg(_) | T::CmdArg(_) | T::InitArg(_) | T::InitEnvKey(_)
                ) =>
            {
                return invalid(
                    "SCFG_BINDING",
                    target.field(),
                    "excluded positional or init input needs a binding",
                );
            }
            RuntimeCaptureAction::Omit => {}
        }
    }
    Ok(())
}
