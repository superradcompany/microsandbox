//! Select the saved runtime overlay without copying destination credentials into metadata.

use std::collections::{BTreeMap, BTreeSet};

use microsandbox_types::SandboxSpecPatch;
use microsandbox_types::snapshot::saved_config::{SavedRuntimeConfig, SavedText, SavedValue};

use super::{
    RuntimeDefaultClear, RuntimeDefaultSelection, RuntimeSelectionContext, SnapshotConfigMode,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select only the surviving saved runtime defaults beneath an existing sparse destination patch.
///
/// This is one stage of the complete resolver, not a launch-ready config. It does not
/// read files, resolve bindings, execute scripts, change source metadata, or apply a
/// source-supplied permission. The explicit patch must retain its existing layer order.
/// Full-state script overrides are returned as proof obligations, never approved here.
pub fn select_runtime_defaults(
    saved: &SavedRuntimeConfig,
    explicit: &SandboxSpecPatch,
    clears: &[RuntimeDefaultClear],
    context: RuntimeSelectionContext,
) -> MicrosandboxResult<RuntimeDefaultSelection> {
    saved
        .validate_active()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    if context.full_resume && context.starts_command {
        return invalid(
            "SCFG_MODE",
            "runtime.cmd",
            "a new initial command requires disk boot",
        );
    }
    if context.full_resume && (explicit.init.is_some() || explicit.runtime.hostname.is_some()) {
        return invalid(
            "SCFG_FULL_STATE",
            "runtime",
            "init and hostname overrides cannot change captured execution",
        );
    }
    if clears.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES {
        return invalid("SCFG_LIMIT", "runtime.clear", "too many clear selectors");
    }
    // Validate every selector against the same source, so duplicate/redundant
    // clears are idempotent and do not become order-dependent missing-key errors.
    for clear in clears {
        validate_clear(saved, clear, context.full_resume)?;
    }
    let mut defaults = saved.clone();
    for clear in clears {
        apply_clear(&mut defaults, clear);
    }
    if context.config_mode == SnapshotConfigMode::Fresh {
        // Fresh discards optional defaults. Captured PID 1, hostname, script
        // backing and clock policy still need independent full-state admission.
        defaults = if context.full_resume {
            SavedRuntimeConfig {
                init: defaults.init,
                hostname: defaults.hostname,
                scripts: defaults.scripts,
                guest_clock: defaults.guest_clock,
                ..Default::default()
            }
        } else {
            SavedRuntimeConfig::default()
        };
    }
    let changed_entrypoint = explicit
        .runtime
        .entrypoint
        .as_ref()
        .is_some_and(|entrypoint| !literal_argv_matches(defaults.entrypoint.as_ref(), entrypoint));
    // A separate result flag prevents a consumer from dropping saved CMD only to
    // accidentally revive the older image CMD underneath it. The final integration
    // must consume this flag before explicit command inputs apply. This rule is
    // specific to saved snapshot defaults, not ordinary image-only merging.
    let reset_inherited_cmd = context.config_mode == SnapshotConfigMode::Saved
        && changed_entrypoint
        && defaults.cmd.is_some()
        && explicit.runtime.cmd.is_none();
    if reset_inherited_cmd {
        defaults.cmd = None;
    }
    if explicit.runtime.workdir.is_some() {
        defaults.workdir = None;
    }
    if explicit.runtime.shell.is_some() {
        defaults.shell = None;
    }
    if explicit.runtime.entrypoint.is_some() {
        defaults.entrypoint = None;
    }
    if explicit.runtime.cmd.is_some() {
        defaults.cmd = None;
    }
    if explicit.runtime.user.is_some() {
        defaults.user = None;
    }
    if explicit.runtime.guest_clock.is_some() {
        defaults.guest_clock = None;
    }
    if explicit.runtime.hostname.is_some() {
        defaults.hostname = None;
    }
    // Init is a complete selection. Its arguments and environment cannot leak
    // into an explicit replacement init, including an explicit auto selection.
    if explicit.init.is_some() {
        defaults.init = None;
    }
    if explicit.replaces_env() {
        defaults.env = None;
    } else if let Some(env) = explicit.get_env() {
        mask_keys(
            &mut defaults.env,
            env.iter().map(|entry| entry.key.as_str()),
        );
    }
    let mut scripts_requiring_identity_check = BTreeSet::new();
    let script_replacement_requires_identity_check =
        context.full_resume && explicit.runtime.replaces_scripts();
    if context.full_resume {
        if let Some(scripts) = explicit.runtime.get_scripts() {
            scripts_requiring_identity_check.extend(scripts.keys().cloned());
        }
        // Keep captured script evidence even when the higher patch replaces the
        // whole map. The identity checker needs the original backing/content.
    } else if explicit.runtime.replaces_scripts() {
        defaults.scripts = None;
    } else if let Some(scripts) = explicit.runtime.get_scripts() {
        mask_keys(&mut defaults.scripts, scripts.keys().map(String::as_str));
    }
    let binding_requirements = defaults
        .binding_requirements()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    let unknown_fields = unknown_fields(&defaults);
    Ok(RuntimeDefaultSelection {
        defaults,
        reset_inherited_cmd,
        scripts_requiring_identity_check,
        script_replacement_requires_identity_check,
        binding_requirements,
        unknown_fields,
    })
}

fn validate_clear(
    runtime: &SavedRuntimeConfig,
    clear: &RuntimeDefaultClear,
    full: bool,
) -> MicrosandboxResult<()> {
    if full
        && matches!(
            clear,
            RuntimeDefaultClear::Init
                | RuntimeDefaultClear::Hostname
                | RuntimeDefaultClear::Scripts
                | RuntimeDefaultClear::ScriptKey(_)
                | RuntimeDefaultClear::GuestClock
        )
    {
        return invalid(
            "SCFG_FULL_STATE",
            "runtime",
            "cannot clear captured init, hostname, clock or script requirements",
        );
    }
    match clear {
        RuntimeDefaultClear::EnvKey(key) => validate_key(&runtime.env, key, "runtime.env"),
        RuntimeDefaultClear::ScriptKey(key) => {
            validate_key(&runtime.scripts, key, "runtime.scripts")
        }
        _ => Ok(()),
    }
}

fn apply_clear(runtime: &mut SavedRuntimeConfig, clear: &RuntimeDefaultClear) {
    match clear {
        RuntimeDefaultClear::Workdir => runtime.workdir = None,
        RuntimeDefaultClear::Shell => runtime.shell = None,
        RuntimeDefaultClear::Entrypoint => runtime.entrypoint = None,
        RuntimeDefaultClear::Cmd => runtime.cmd = None,
        RuntimeDefaultClear::Env => runtime.env = None,
        RuntimeDefaultClear::EnvKey(key) => {
            mask_keys(&mut runtime.env, std::iter::once(key.as_str()))
        }
        RuntimeDefaultClear::Scripts => runtime.scripts = None,
        RuntimeDefaultClear::ScriptKey(key) => {
            mask_keys(&mut runtime.scripts, std::iter::once(key.as_str()))
        }
        RuntimeDefaultClear::Init => runtime.init = None,
        RuntimeDefaultClear::Hostname => runtime.hostname = None,
        RuntimeDefaultClear::User => runtime.user = None,
        RuntimeDefaultClear::GuestClock => runtime.guest_clock = None,
    }
}

fn validate_key<T>(
    field: &Option<SavedValue<BTreeMap<String, T>>>,
    key: &str,
    path: &str,
) -> MicrosandboxResult<()> {
    if let Some(SavedValue::Value { value, .. }) = field
        && value.contains_key(key)
    {
        return Ok(());
    }
    invalid(
        "SCFG_CLEAR",
        path,
        "selected key is not recorded; use a whole-field clear for unavailable defaults",
    )
}

fn mask_keys<'a, T>(
    field: &mut Option<SavedValue<BTreeMap<String, T>>>,
    keys: impl Iterator<Item = &'a str>,
) {
    if let Some(SavedValue::Value { value, .. }) = field {
        for key in keys {
            value.remove(key);
        }
    }
}

fn literal_argv_matches(saved: Option<&SavedValue<Vec<SavedText>>>, explicit: &[String]) -> bool {
    saved.and_then(SavedValue::value).is_some_and(|argv| {
        argv.len() == explicit.len()
            && argv.iter().zip(explicit).all(
                |(saved, explicit)| matches!(saved,SavedText::Literal {value} if value==explicit),
            )
    })
}

fn is_unknown<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(value, Some(SavedValue::Unknown { .. }))
}

fn unknown_fields(runtime: &SavedRuntimeConfig) -> BTreeSet<&'static str> {
    // Exhaustive destructuring forces newly added runtime fields to receive a
    // resolution rule rather than silently becoming an unclassified default.
    let SavedRuntimeConfig {
        workdir,
        shell,
        entrypoint,
        cmd,
        env,
        scripts,
        init,
        hostname,
        user,
        guest_clock,
    } = runtime;
    [
        ("runtime.workdir", is_unknown(workdir)),
        ("runtime.shell", is_unknown(shell)),
        ("runtime.entrypoint", is_unknown(entrypoint)),
        ("runtime.cmd", is_unknown(cmd)),
        ("runtime.env", is_unknown(env)),
        ("runtime.scripts", is_unknown(scripts)),
        ("runtime.init", is_unknown(init)),
        ("runtime.hostname", is_unknown(hostname)),
        ("runtime.user", is_unknown(user)),
        ("runtime.guest_clock", is_unknown(guest_clock)),
    ]
    .into_iter()
    .filter_map(|(field, unknown)| unknown.then_some(field))
    .collect()
}

fn invalid<T>(code: &str, field: &str, reason: &str) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::InvalidConfig(format!(
        "{code}: {field}: {reason}"
    )))
}
