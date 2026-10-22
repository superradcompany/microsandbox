//! Prepare selected runtime values without converting destination secrets into portable literals.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_types::GuestClockPolicy;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES,
    MAX_SAVED_SCRIPTS_BYTES, MAX_SAVED_TEXT_BYTES, RuntimeBindingConsumer, SavedHostname,
    SavedInit, SavedRuntimeConfig, SavedScript, SavedText, SavedUnknownReason, SavedValue,
};
use zeroize::Zeroizing;

use super::{RuntimeDefaultSelection, RuntimeSelectionContext};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit destination text; no environment/store/file lookup is performed here.
#[derive(Clone)]
pub struct RuntimeBindingInput {
    /// Prepared UTF-8 content, cleared when this buffer is dropped.
    pub text: Zeroizing<String>,
    /// Required when the ID supplies a script. Never guess a captured executable mode.
    pub script_mode: Option<u16>,
}

/// Preserve every saved state while distinguishing unresolved future consumers from unknown
/// source observations. No variant implements serialization or prints contained values.
pub enum PreparedRuntimeValue<T> {
    /// Omitted source default; retain the documented destination fallback.
    Omitted,
    /// Explicit builtin/default selection, not omission.
    Default,
    /// No confirmed source value exists.
    Unknown(SavedUnknownReason),
    /// Exact selected literal or resolved destination value.
    Ready(T),
    /// A future consumer must re-prepare from retained references before execution.
    Deferred(BTreeSet<String>),
}

/// Exact script backing, separate from the ordinary runtime script wrapper/materializer.
pub struct PreparedRuntimeScript {
    /// Exact normalized UTF-8 bytes. These are never executed by preparation.
    pub content: Zeroizing<String>,
    /// Exact permission bits; no setuid/setgid/sticky bits are accepted.
    pub mode: u16,
}

/// A resolved init choice, used only for cold boot, never to replace captured PID 1.
pub enum PreparedRuntimeInit {
    /// Minimal microsandbox init/agent boot.
    Builtin,
    /// Use the recorded resolved guest path even if the original selection was auto.
    Handoff {
        /// Absolute guest path, already validated in the source metadata.
        path: String,
        /// Exact supplemental arguments without another shell wrapping pass.
        args: Zeroizing<Vec<String>>,
        /// Init-only environment, kept separate from new-command defaults.
        env: BTreeMap<String, Zeroizing<String>>,
    },
}

/// In-memory consumer inputs only; no ready-to-launch configuration or persisted credentials.
pub struct RuntimeInputPlan {
    /// Working directory for new processes.
    pub workdir: PreparedRuntimeValue<String>,
    /// Shell choice for new processes; no script rewrapping occurs here.
    pub shell: PreparedRuntimeValue<String>,
    /// Complete entrypoint argv or an unresolved whole-field requirement.
    pub entrypoint: PreparedRuntimeValue<Zeroizing<Vec<String>>>,
    /// Complete configured CMD, separate from an ancestor's one-shot invocation.
    pub cmd: PreparedRuntimeValue<Zeroizing<Vec<String>>>,
    /// Complete selected environment, without partially dropping required keys.
    pub env: PreparedRuntimeValue<BTreeMap<String, Zeroizing<String>>>,
    /// Init inputs for a cold boot, including a later boot after full resume.
    pub init: PreparedRuntimeValue<PreparedRuntimeInit>,
    /// Exact backing bytes and permission bits for registered scripts.
    pub scripts: PreparedRuntimeValue<BTreeMap<String, PreparedRuntimeScript>>,
    /// Generated identity remains tagged and must be regenerated for a new disk boot.
    pub hostname: PreparedRuntimeValue<SavedHostname>,
    /// Identity for newly started processes, not credentials of captured processes.
    pub user: PreparedRuntimeValue<String>,
    /// Selected clock policy, still subject to authoritative full-state checks.
    pub guest_clock: PreparedRuntimeValue<GuestClockPolicy>,
    /// Original selected references for future re-preparation and capture provenance. Never
    /// replace their binding references with resolved credentials when storing configuration.
    pub retained: SavedRuntimeConfig,
    /// Must suppress older image CMD fallback before explicit destination inputs apply.
    pub reset_inherited_cmd: bool,
    /// Explicit full-resume script overrides still need captured-backing proof.
    pub scripts_requiring_identity_check: BTreeSet<String>,
    /// Empty explicit script-map replacement also requires backing admission.
    pub script_replacement_requires_identity_check: bool,
    /// Full-state script/backing, init, hostname and clock admission is still mandatory.
    pub requires_full_identity: bool,
}

#[derive(Default)]
struct PreparationBudget {
    bytes: usize,
    script_bytes: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> PreparedRuntimeValue<T> {
    /// Refuse unknown or unresolved input before a consumer reads its value. Default and
    /// omitted states remain explicit so the assembler can apply their different semantics.
    pub fn require_available(&self, field: &'static str) -> MicrosandboxResult<()> {
        match self {
            Self::Unknown(_) => Err(error(
                "SCFG_UNKNOWN",
                field,
                "source value is unknown; override or clear it",
            )),
            Self::Deferred(_) => Err(error(
                "SCFG_BINDING",
                field,
                "required destination inputs are missing",
            )),
            _ => Ok(()),
        }
    }
}

impl PreparationBudget {
    fn add(&mut self, value: &str, script: bool) -> MicrosandboxResult<()> {
        let limit = if script {
            MAX_SAVED_SCRIPT_BYTES
        } else {
            MAX_SAVED_TEXT_BYTES
        };
        if value.len() > limit || (!script && value.contains('\0')) {
            return Err(error(
                "SCFG_VALUE",
                "runtime",
                "invalid or oversized destination value",
            ));
        }
        self.bytes = self.bytes.checked_add(value.len()).ok_or_else(|| {
            error(
                "SCFG_LIMIT",
                "runtime",
                "expanded runtime inputs are too large",
            )
        })?;
        if script {
            self.script_bytes += value.len();
        }
        if self.bytes > MAX_SAVED_CONFIG_BYTES || self.script_bytes > MAX_SAVED_SCRIPTS_BYTES {
            return Err(error(
                "SCFG_LIMIT",
                "runtime",
                "expanded runtime inputs are too large",
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for RuntimeBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeBindingInput")
            .field("has_script_mode", &self.script_mode.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> fmt::Debug for PreparedRuntimeValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Omitted => f.write_str("Omitted"),
            Self::Default => f.write_str("Default"),
            Self::Unknown(reason) => f.debug_tuple("Unknown").field(reason).finish(),
            Self::Ready(_) => f.write_str("Ready(..)"),
            Self::Deferred(ids) => f
                .debug_struct("Deferred")
                .field("binding_count", &ids.len())
                .finish(),
        }
    }
}

impl fmt::Debug for PreparedRuntimeScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedRuntimeScript")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PreparedRuntimeInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedRuntimeInit(..)")
    }
}

impl fmt::Debug for RuntimeInputPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeInputPlan")
            .field("entrypoint", &self.entrypoint)
            .field("cmd", &self.cmd)
            .field("env", &self.env)
            .field("init", &self.init)
            .field("scripts", &self.scripts)
            .field("reset_inherited_cmd", &self.reset_inherited_cmd)
            .field("requires_full_identity", &self.requires_full_identity)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize already selected runtime inputs. A missing future-command value defers the
/// entire corresponding field, never a shortened argv or environment missing a required key.
/// Initial commands, cold init and script backing must have their inputs available now.
///
/// The caller supplies only this section's binding inputs and must also enforce combined
/// selected/captured demand: a future env binding may still be immediate for a gateway or
/// captured process. Full-state identity checks and deferred exec persistence remain outside
/// this pure preparation step. No source lookup, script wrapping, file write or execution occurs.
pub fn prepare_runtime_inputs(
    selection: &RuntimeDefaultSelection,
    inputs: &BTreeMap<String, RuntimeBindingInput>,
    context: RuntimeSelectionContext,
) -> MicrosandboxResult<RuntimeInputPlan> {
    if context.full_resume && context.starts_command {
        return Err(error(
            "SCFG_MODE",
            "runtime",
            "full resume cannot start a new initial command",
        ));
    }
    let saved = &selection.defaults;
    saved
        .validate_active()
        .map_err(|_| error("SCFG_VALUE", "runtime", "invalid active runtime metadata"))?;
    let uses = saved
        .binding_requirements()
        .map_err(|_| error("SCFG_VALUE", "runtime", "invalid selected runtime metadata"))?;
    if inputs.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error(
            "SCFG_LIMIT",
            "runtime.bindings",
            "too many destination bindings",
        ));
    }
    for (id, input) in inputs {
        let consumers = uses.get(id).ok_or_else(|| {
            error(
                "SCFG_BINDING",
                "runtime.bindings",
                "binding has no selected runtime consumer",
            )
        })?;
        let script = consumers.contains(&RuntimeBindingConsumer::ScriptBacking);
        if script != input.script_mode.is_some()
            || input.script_mode.is_some_and(|mode| mode > 0o777)
        {
            return Err(error(
                "SCFG_BINDING",
                "runtime.scripts",
                "script bindings require explicit permission bits; other inputs must not set them",
            ));
        }
    }
    let mut budget = PreparationBudget::default();
    let entrypoint = text_list(saved.entrypoint.as_ref(), inputs, &mut budget)?;
    let cmd = text_list(saved.cmd.as_ref(), inputs, &mut budget)?;
    let env = text_env(saved.env.as_ref(), inputs, &mut budget)?;
    let init = prepare_value(saved.init.as_ref(), |init, missing| match init {
        SavedInit::Builtin {} => Ok(PreparedRuntimeInit::Builtin),
        SavedInit::RequestedHandoff { .. } => Err(error(
            "SCFG_IDENTITY",
            "runtime.init",
            "pending init cannot be activated as saved state",
        )),
        SavedInit::Handoff {
            resolved_path,
            args,
            env,
            ..
        } => Ok(PreparedRuntimeInit::Handoff {
            path: resolved_path.clone(),
            args: resolve_list(args, inputs, missing, &mut budget)?,
            env: resolve_env(env, inputs, missing, &mut budget)?,
        }),
    })?;
    let scripts = prepare_value(saved.scripts.as_ref(), |scripts, missing| {
        let mut prepared = BTreeMap::new();
        for (name, script) in scripts {
            let (content, mode) = match script {
                SavedScript::Declaration { .. } => {
                    return Err(error(
                        "SCFG_IDENTITY",
                        "runtime.scripts",
                        "pending script cannot be activated as saved backing",
                    ));
                }
                SavedScript::Inline { content, mode, .. } => (content.as_str(), *mode),
                SavedScript::Binding { id } => match inputs.get(id) {
                    Some(input) => (
                        input.text.as_str(),
                        input.script_mode.expect("validated script mode"),
                    ),
                    None => {
                        missing.insert(id.clone());
                        continue;
                    }
                },
            };
            budget.add(content, true)?;
            prepared.insert(
                name.clone(),
                PreparedRuntimeScript {
                    content: Zeroizing::new(content.to_owned()),
                    mode,
                },
            );
        }
        Ok(prepared)
    })?;
    let plan = RuntimeInputPlan {
        workdir: literal(saved.workdir.as_ref()),
        shell: literal(saved.shell.as_ref()),
        entrypoint,
        cmd,
        env,
        init,
        scripts,
        hostname: literal(saved.hostname.as_ref()),
        user: literal(saved.user.as_ref()),
        guest_clock: literal(saved.guest_clock.as_ref()),
        retained: saved.clone(),
        reset_inherited_cmd: selection.reset_inherited_cmd,
        requires_full_identity: context.full_resume,
        scripts_requiring_identity_check: selection.scripts_requiring_identity_check.clone(),
        script_replacement_requires_identity_check: selection
            .script_replacement_requires_identity_check,
    };
    plan.scripts.require_available("runtime.scripts")?;
    if !context.full_resume {
        plan.init.require_available("runtime.init")?;
    }
    if context.starts_command {
        plan.entrypoint.require_available("runtime.entrypoint")?;
        plan.cmd.require_available("runtime.cmd")?;
        plan.env.require_available("runtime.env")?;
        plan.workdir.require_available("runtime.workdir")?;
        plan.shell.require_available("runtime.shell")?;
        plan.user.require_available("runtime.user")?;
    }
    Ok(plan)
}

fn literal<T: Clone>(saved: Option<&SavedValue<T>>) -> PreparedRuntimeValue<T> {
    match saved {
        None => PreparedRuntimeValue::Omitted,
        Some(SavedValue::Default {}) => PreparedRuntimeValue::Default,
        Some(SavedValue::Unknown { reason }) => PreparedRuntimeValue::Unknown(*reason),
        Some(SavedValue::Value { value, .. }) => PreparedRuntimeValue::Ready(value.clone()),
    }
}

fn prepare_value<T, U>(
    saved: Option<&SavedValue<T>>,
    resolve: impl FnOnce(&T, &mut BTreeSet<String>) -> MicrosandboxResult<U>,
) -> MicrosandboxResult<PreparedRuntimeValue<U>> {
    Ok(match saved {
        None => PreparedRuntimeValue::Omitted,
        Some(SavedValue::Default {}) => PreparedRuntimeValue::Default,
        Some(SavedValue::Unknown { reason }) => PreparedRuntimeValue::Unknown(*reason),
        Some(SavedValue::Value { value, .. }) => {
            let mut missing = BTreeSet::new();
            let ready = resolve(value, &mut missing)?;
            if missing.is_empty() {
                PreparedRuntimeValue::Ready(ready)
            } else {
                PreparedRuntimeValue::Deferred(missing)
            }
        }
    })
}

fn text_list(
    saved: Option<&SavedValue<Vec<SavedText>>>,
    inputs: &BTreeMap<String, RuntimeBindingInput>,
    budget: &mut PreparationBudget,
) -> MicrosandboxResult<PreparedRuntimeValue<Zeroizing<Vec<String>>>> {
    prepare_value(saved, |values, missing| {
        resolve_list(values, inputs, missing, budget)
    })
}

fn text_env(
    saved: Option<&SavedValue<BTreeMap<String, SavedText>>>,
    inputs: &BTreeMap<String, RuntimeBindingInput>,
    budget: &mut PreparationBudget,
) -> MicrosandboxResult<PreparedRuntimeValue<BTreeMap<String, Zeroizing<String>>>> {
    prepare_value(saved, |values, missing| {
        resolve_env(values, inputs, missing, budget)
    })
}

fn resolve_list(
    values: &[SavedText],
    inputs: &BTreeMap<String, RuntimeBindingInput>,
    missing: &mut BTreeSet<String>,
    budget: &mut PreparationBudget,
) -> MicrosandboxResult<Zeroizing<Vec<String>>> {
    let mut result = Zeroizing::new(Vec::new());
    for value in values {
        if let Some(text) = resolve_text(value, inputs, missing) {
            budget.add(text, false)?;
            result.push(text.to_owned());
        }
    }
    Ok(result)
}

fn resolve_env(
    values: &BTreeMap<String, SavedText>,
    inputs: &BTreeMap<String, RuntimeBindingInput>,
    missing: &mut BTreeSet<String>,
    budget: &mut PreparationBudget,
) -> MicrosandboxResult<BTreeMap<String, Zeroizing<String>>> {
    let mut result = BTreeMap::new();
    for (key, value) in values {
        if let Some(text) = resolve_text(value, inputs, missing) {
            budget.add(text, false)?;
            result.insert(key.clone(), Zeroizing::new(text.to_owned()));
        }
    }
    Ok(result)
}

fn resolve_text<'a>(
    value: &'a SavedText,
    inputs: &'a BTreeMap<String, RuntimeBindingInput>,
    missing: &mut BTreeSet<String>,
) -> Option<&'a str> {
    match value {
        SavedText::Literal { value } => Some(value),
        SavedText::Binding { id } => match inputs.get(id) {
            Some(input) => Some(input.text.as_str()),
            None => {
                missing.insert(id.clone());
                None
            }
        },
    }
}

fn error(code: &str, field: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: {field}: {reason}"))
}
