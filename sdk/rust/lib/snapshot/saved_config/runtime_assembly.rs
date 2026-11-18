//! Assemble selected runtime defaults without installing files or authorizing execution.

use std::collections::BTreeMap;
use std::fmt;

use microsandbox_types::snapshot::saved_config::{SavedHostname, SavedRuntimeConfig};
use microsandbox_types::{
    EnvVar, HandoffInit, SandboxRuntimeOptions, SandboxSpec, SandboxSpecPatch,
};
use zeroize::Zeroizing;

use super::{
    PreparedRuntimeInit, PreparedRuntimeScript, PreparedRuntimeValue, RuntimeBindingInput,
    RuntimeDefaultClear, RuntimeInputPlan, RuntimeSelectionContext, prepare_runtime_inputs,
    select_runtime_defaults,
};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Native command defaults plus separate init/backing plans. This type deliberately cannot
/// serialize or become a SandboxSpec: deferred consumers and full-state proof still need gates.
pub struct RuntimeConfigurationPlan {
    runtime: SandboxRuntimeOptions,
    env: Vec<EnvVar>,
    cold_boot_init: Option<HandoffInit>,
    /// Exact selected script bytes/modes; the ordinary script writer must not rewrap them or
    /// replace their modes with 0755. Full resume still checks original captured backing.
    scripts: BTreeMap<String, PreparedRuntimeScript>,
    /// Selected portable references and unresolved/full-state obligations survive assembly.
    inputs: RuntimeInputPlan,
}

/// Defaults for a newly created process, never a request to rerun captured processes.
/// Its value-bearing Debug output is deliberately redacted.
pub struct PreparedCommandDefaults {
    /// Native runtime settings. Scripts are separate exact backing, not ordinary script strings.
    pub runtime: SandboxRuntimeOptions,
    /// Complete environment selected for a new process.
    pub env: Vec<EnvVar>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeConfigurationPlan {
    pub(super) fn apply_activation_inputs(
        &self,
        target: &mut SandboxSpec,
        context: RuntimeSelectionContext,
    ) -> MicrosandboxResult<()> {
        // Scripts/identity/clock are activation inputs even when no new command runs.
        // Command and init requirements have different timing and remain on `inputs`.
        self.inputs.hostname.require_available("runtime.hostname")?;
        self.inputs
            .guest_clock
            .require_available("runtime.guest_clock")?;
        self.inputs.scripts.require_available("runtime.scripts")?;
        if context.starts_command {
            self.require_command_defaults()?;
        }
        let init = if context.full_resume {
            None // Captured PID 1 is authoritative; never replay the cold-boot choice.
        } else {
            self.cold_boot_init()?
        };
        target.runtime = self.runtime.clone();
        target.env = self.env.clone();
        target.init = init;
        Ok(())
    }

    /// Read the original preparation obligations without mutating readiness after assembly.
    pub fn inputs(&self) -> &RuntimeInputPlan {
        &self.inputs
    }

    /// Read exact backing without routing it through the ordinary script-string materializer.
    pub fn scripts(&self) -> &BTreeMap<String, PreparedRuntimeScript> {
        &self.scripts
    }

    /// Return new-command defaults only when every selected command field is available.
    /// A later explicit command override must reselect/reprepare from retained references;
    /// this cannot silently bypass missing bindings by using older image defaults.
    pub fn command_defaults(&self) -> MicrosandboxResult<PreparedCommandDefaults> {
        self.require_command_defaults()?;
        Ok(PreparedCommandDefaults {
            runtime: self.runtime.clone(),
            env: self.env.clone(),
        })
    }

    /// Cold-boot init only. Full resume must never feed this into captured PID 1; retain the
    /// requirement for a later cold boot and recheck destination bindings at that time.
    pub fn cold_boot_init(&self) -> MicrosandboxResult<Option<HandoffInit>> {
        self.inputs.init.require_available("runtime.init")?;
        Ok(self.cold_boot_init.clone())
    }

    fn require_command_defaults(&self) -> MicrosandboxResult<()> {
        // Assembly checks readiness without cloning potentially large command/environment
        // values merely to discard them; both access paths use exactly the same guard.
        self.inputs
            .entrypoint
            .require_available("runtime.entrypoint")?;
        self.inputs.cmd.require_available("runtime.cmd")?;
        self.inputs.env.require_available("runtime.env")?;
        self.inputs.workdir.require_available("runtime.workdir")?;
        self.inputs.shell.require_available("runtime.shell")?;
        self.inputs.user.require_available("runtime.user")?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for RuntimeConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeConfigurationPlan")
            .field("script_count", &self.scripts.len())
            .field("inputs", &self.inputs)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PreparedCommandDefaults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCommandDefaults")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compose runtime selection, binding preparation and native field assembly in one operation.
/// `lower` already contains resolved destination/image defaults; never reapply image merging
/// afterward. `explicit` retains the existing sparse merge
/// semantics. Only runtime/env/init fields are consumed: unrelated image, network, storage,
/// identity, resource and lifecycle fields never leak through a partial whole-spec apply.
/// Managed constraints, combined binding demand and full-state identity remain later gates.
pub fn prepare_runtime_configuration(
    saved: &SavedRuntimeConfig,
    lower: &SandboxSpec,
    explicit: &SandboxSpecPatch,
    clears: &[RuntimeDefaultClear],
    context: RuntimeSelectionContext,
    bindings: &BTreeMap<String, RuntimeBindingInput>,
) -> MicrosandboxResult<RuntimeConfigurationPlan> {
    let selection = select_runtime_defaults(saved, explicit, clears, context)?;
    let inputs = prepare_runtime_inputs(&selection, bindings, context)?;
    let mut runtime = lower.runtime.clone();
    let mut lower_env = lower.env.clone();
    let mut lower_init = lower.init.clone();
    // A structural clear removes the named default even if an older image layer also
    // supplied it. Apply clears before the higher explicit patch; unrelated keys survive.
    for clear in clears {
        match clear {
            RuntimeDefaultClear::Workdir => runtime.workdir = None,
            RuntimeDefaultClear::Shell => runtime.shell = None,
            RuntimeDefaultClear::Entrypoint => runtime.entrypoint = Some(Vec::new()),
            RuntimeDefaultClear::Cmd => runtime.cmd = Some(Vec::new()),
            RuntimeDefaultClear::Env => lower_env.clear(),
            RuntimeDefaultClear::EnvKey(key) => lower_env.retain(|v| &v.key != key),
            RuntimeDefaultClear::Scripts => runtime.scripts.clear(),
            RuntimeDefaultClear::ScriptKey(key) => {
                runtime.scripts.remove(key);
            }
            RuntimeDefaultClear::Init => lower_init = None,
            RuntimeDefaultClear::Hostname => runtime.hostname = None,
            RuntimeDefaultClear::User => runtime.user = None,
            RuntimeDefaultClear::GuestClock => runtime.guest_clock = None,
        }
    }
    // Known complete maps replace the lower map before destination per-key merge. Unknown
    // or deferred maps must not expose an apparently usable subset inherited from an image.
    let mut env = match &inputs.env {
        PreparedRuntimeValue::Omitted => lower_env,
        PreparedRuntimeValue::Ready(values) => values
            .iter()
            .map(|(key, value)| EnvVar {
                key: key.clone(),
                value: value.to_string(),
            })
            .collect(),
        _ => Vec::new(),
    };
    scalar(&mut runtime.workdir, &inputs.workdir);
    scalar(&mut runtime.shell, &inputs.shell);
    scalar(&mut runtime.user, &inputs.user);
    scalar(&mut runtime.guest_clock, &inputs.guest_clock);
    argv(&mut runtime.entrypoint, &inputs.entrypoint);
    argv(&mut runtime.cmd, &inputs.cmd);
    if inputs.reset_inherited_cmd {
        // Some(empty), rather than None, also blocks the downstream image-default merger.
        runtime.cmd = Some(Vec::new());
    }
    match &inputs.hostname {
        PreparedRuntimeValue::Omitted => {}
        PreparedRuntimeValue::Ready(SavedHostname::Explicit { value }) => {
            runtime.hostname = Some(value.clone())
        }
        PreparedRuntimeValue::Ready(SavedHostname::Generated { value }) if context.full_resume => {
            // Captured identity remains evidence, never a new host allocation. The full-state
            // checker must compare this with independently restored guest identity.
            runtime.hostname = Some(value.clone());
        }
        _ => runtime.hostname = None,
    }
    let mut cold_boot_init = match &inputs.init {
        PreparedRuntimeValue::Omitted => lower_init,
        PreparedRuntimeValue::Ready(PreparedRuntimeInit::Handoff { path, args, env }) => {
            Some(HandoffInit {
                cmd: path.clone(),
                args: args.to_vec(),
                env: env
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_string()))
                    .collect(),
            })
        }
        _ => None,
    };
    let mut scripts = match &inputs.scripts {
        PreparedRuntimeValue::Omitted => runtime
            .scripts
            .iter()
            .map(|(name, body)| {
                (
                    name.clone(),
                    PreparedRuntimeScript {
                        content: Zeroizing::new(body.clone()),
                        mode: 0o755,
                    },
                )
            })
            .collect(),
        PreparedRuntimeValue::Ready(values) => values
            .iter()
            .map(|(name, script)| {
                (
                    name.clone(),
                    PreparedRuntimeScript {
                        content: script.content.clone(),
                        mode: script.mode,
                    },
                )
            })
            .collect(),
        _ => BTreeMap::new(),
    };
    if explicit.runtime.replaces_scripts() {
        scripts.clear();
    }
    if let Some(values) = explicit.runtime.get_scripts() {
        for (name, body) in values {
            // Ordinary explicit scripts follow the existing native-body/0755
            // contract. Bound saved scripts retain their separately supplied exact mode.
            scripts.insert(
                name.clone(),
                PreparedRuntimeScript {
                    content: Zeroizing::new(body.clone()),
                    mode: 0o755,
                },
            );
        }
    }
    explicit.runtime.clone().apply_to(&mut runtime);
    // Never route exact saved backing through the ordinary startup script materializer.
    runtime.scripts.clear();
    if explicit.replaces_env() {
        env.clear();
    }
    if let Some(values) = explicit.get_env() {
        for entry in values {
            if let Some(previous) = env.iter_mut().find(|v| v.key == entry.key) {
                previous.value.clone_from(&entry.value);
            } else {
                env.push(entry.clone());
            }
        }
    }
    if let Some(init) = &explicit.init {
        cold_boot_init = Some(init.clone());
    }
    Ok(RuntimeConfigurationPlan {
        runtime,
        env,
        cold_boot_init,
        scripts,
        inputs,
    })
}

fn scalar<T: Clone>(target: &mut Option<T>, value: &PreparedRuntimeValue<T>) {
    match value {
        PreparedRuntimeValue::Omitted => {}
        PreparedRuntimeValue::Ready(value) => *target = Some(value.clone()),
        _ => *target = None,
    }
}

fn argv(target: &mut Option<Vec<String>>, value: &PreparedRuntimeValue<Zeroizing<Vec<String>>>) {
    match value {
        PreparedRuntimeValue::Omitted => {}
        PreparedRuntimeValue::Ready(value) => *target = Some(value.to_vec()),
        // Default means no configured command, and must suppress image fallback just like
        // explicit empty argv. Deferred/unknown fields are guarded by command_defaults().
        _ => *target = Some(Vec::new()),
    }
}
