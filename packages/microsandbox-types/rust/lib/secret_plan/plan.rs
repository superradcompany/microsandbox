//! The secret planner: changes, dispositions, conflicts and refusals, plus the
//! classifier for non-secret configuration changes.

use std::collections::{BTreeMap, BTreeSet};

use super::input::{
    DesiredMaterial, DesiredSecret, RunningSecret, SecretPlanCapability, SecretPlanInput,
    SecretPlanStatus, SecretSettings, default_placeholder,
};
use crate::domain::SecretSubstitution;
use crate::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, SandboxModificationPlan,
    SecretChangeKind, SecretPlannedChange, SecretSource,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Plan field of every secret change, conflict and warning.
pub const SECRET_FIELD: &str = "secret";

/// Reason and warning for a live-capable change the backend cannot deliver live.
pub const LIVE_SECRET_RECONFIGURE_UNAVAILABLE: &str =
    "live secret reconfiguration is not available in this runtime yet";

const SECRET_POLICY_REQUIRES_RESTART: &str =
    "secret policy changes require restart; use restart or next_start";
const SECRET_PLACEHOLDER_REQUIRES_RESTART: &str =
    "guest-visible secret placeholders cannot be introduced into existing processes";
const SECRETS_UNSUPPORTED: &str = "secret modification requires a build with the net feature";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One aspect of a secret that a plan changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretAspect {
    /// The secret is new.
    Added,

    /// The secret gets new material.
    Rotated,

    /// The allowed hosts change.
    HostsUpdated,

    /// The guest-visible placeholder changes.
    PlaceholderUpdated,

    /// The secret's policy changes: substitution, passthrough hosts, violation
    /// action or TLS identity.
    PolicyUpdated,

    /// The secret is removed.
    Removed,
}

/// What the planner produced for one secret patch.
#[derive(Debug, Clone, Default)]
pub struct SecretPlanOutput {
    /// Planned changes, in patch order: specs first, then removals.
    pub changes: Vec<PlannedChange>,

    /// Conflicts that block applying the patch.
    pub conflicts: Vec<ModificationConflict>,

    /// Warnings about how the changes take effect.
    pub warnings: Vec<ModificationWarning>,

    /// Every aspect each changed secret changes, by the same comparisons as
    /// `changes`. A plan entry carries one kind; this lists all of them.
    pub aspects: BTreeMap<String, BTreeSet<SecretAspect>>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Plan a secret patch against the saved settings and the running sandbox.
///
/// Pure: reads only `input`. Comparison is plain equality, so host order counts.
pub fn plan(input: &SecretPlanInput<'_>) -> SecretPlanOutput {
    let mut output = SecretPlanOutput::default();
    push_secret_changes(input, &mut output);
    push_secret_conflicts(input, &mut output.conflicts);
    output
}

/// Why a plan cannot be applied by a backend with `capability`, if it cannot.
///
/// Reads every entry of the plan, configuration changes included.
pub fn refusal_reason(
    plan: &SandboxModificationPlan,
    capability: SecretPlanCapability,
) -> Option<String> {
    if let Some(conflict) = plan.conflicts.first() {
        return Some(format!("cannot apply modification: {}", conflict.message));
    }

    for change in &plan.changes {
        let (subject, disposition, reason) = match change {
            PlannedChange::Config(change) => (change.field.clone(), change.disposition, None),
            PlannedChange::Secret(change) => (
                format!("secret {}", change.name),
                change.disposition,
                change.reason.as_deref(),
            ),
        };
        match disposition {
            ModificationDisposition::Unsupported => {
                let reason = reason
                    .map(|reason| format!(" ({reason})"))
                    .unwrap_or_default();
                return Some(format!(
                    "cannot apply modification: {subject} is unsupported{reason}"
                ));
            }
            ModificationDisposition::RequiresRestart => {
                if plan.policy != ModificationPolicy::Restart {
                    return Some(format!(
                        "cannot apply modification: {subject} requires restart"
                    ));
                }
                if !capability.restart {
                    return Some(format!(
                        "cannot apply modification: {subject} requires restart, and this \
                         sandbox cannot be restarted by modify; use next_start, then stop and \
                         start it"
                    ));
                }
            }
            ModificationDisposition::Live | ModificationDisposition::NextStart => {}
        }
    }

    None
}

/// Plan field of a secret's policy change.
fn secret_policy_field(name: &str) -> String {
    format!("secret.{name}.policy")
}

/// The secret named by a policy change field, `secret.{name}.policy`.
pub fn secret_name_from_policy_field(field: &str) -> Option<&str> {
    field.strip_prefix("secret.")?.strip_suffix(".policy")
}

/// A configuration change, secret or not, classified like every field without
/// a live path.
pub fn config_change(
    field: &str,
    change: ChangeKind,
    before: Option<String>,
    after: Option<String>,
    status: SecretPlanStatus,
    policy: ModificationPolicy,
    running_reason: &str,
) -> PlannedChange {
    PlannedChange::Config(ConfigPlannedChange {
        field: field.to_string(),
        change,
        before,
        after,
        disposition: config_disposition(status, policy),
        reason: config_reason(status, policy, running_reason),
    })
}

fn push_secret_changes(input: &SecretPlanInput<'_>, output: &mut SecretPlanOutput) {
    // A name stated twice is a conflict, and none of its statements is planned.
    let stated_twice = if input.capability.supported {
        let mut names = repeated(input.secrets.iter().map(|spec| spec.name.as_str()));
        names.extend(repeated(input.secrets_remove.iter().map(String::as_str)));
        names
    } else {
        Vec::new()
    };

    for spec in input.secrets {
        if stated_twice.contains(&spec.name.as_str()) {
            continue;
        }
        let saved = saved(input, &spec.name);
        let running = running(input, &spec.name);
        let policy_changed = policy_changes(spec, saved, running);
        let placeholder_changed = placeholder_changes(spec, saved, running);
        let hosts_changed = !spec.allowed_hosts.is_empty()
            && field_changes(
                spec.allowed_hosts.as_slice(),
                |settings| settings.allowed_hosts.as_slice(),
                saved,
                running,
            );
        let Some(change) = infer_secret_change(spec, saved, placeholder_changed, hosts_changed)
        else {
            if policy_changed {
                // Use the existing generic config-change contract: older SDKs
                // need no new SecretChangeKind variant to decode this plan.
                output.changes.push(config_change(
                    &secret_policy_field(&spec.name),
                    ChangeKind::Updated,
                    None,
                    None,
                    input.status,
                    input.policy,
                    SECRET_POLICY_REQUIRES_RESTART,
                ));
                insert_aspects(output, &spec.name, [SecretAspect::PolicyUpdated]);
            }
            continue;
        };

        let (disposition, reason) = if policy_changed {
            (
                config_disposition(input.status, input.policy),
                config_reason(input.status, input.policy, SECRET_POLICY_REQUIRES_RESTART),
            )
        } else {
            let disposition = secret_disposition(input, change, placeholder_changed);
            push_live_secret_warning(
                input,
                change,
                placeholder_changed,
                disposition,
                &mut output.warnings,
            );
            (
                disposition,
                secret_reason(input, change, placeholder_changed, disposition),
            )
        };

        output
            .changes
            .push(PlannedChange::Secret(SecretPlannedChange {
                field: SECRET_FIELD.to_string(),
                name: spec.name.clone(),
                change,
                before_ref: saved.map(|secret| secret.placeholder.clone()),
                after_ref: Some(
                    spec.placeholder
                        .clone()
                        .or_else(|| saved.map(|secret| secret.placeholder.clone()))
                        .unwrap_or_else(|| default_placeholder(&spec.name)),
                ),
                disposition,
                allow_hosts: if spec.allowed_hosts.is_empty() {
                    saved
                        .map(|secret| secret.allowed_hosts.clone())
                        .unwrap_or_default()
                } else {
                    spec.allowed_hosts.clone()
                },
                reason,
            }));

        if change == SecretChangeKind::Added {
            insert_aspects(output, &spec.name, [SecretAspect::Added]);
        } else {
            let aspects = [
                (spec.material.carries_material(), SecretAspect::Rotated),
                (hosts_changed, SecretAspect::HostsUpdated),
                (placeholder_changed, SecretAspect::PlaceholderUpdated),
                (policy_changed, SecretAspect::PolicyUpdated),
            ];
            insert_aspects(
                output,
                &spec.name,
                aspects
                    .into_iter()
                    .filter_map(|(changed, aspect)| changed.then_some(aspect)),
            );
        }
    }

    for name in input.secrets_remove {
        if stated_twice.contains(&name.as_str()) {
            continue;
        }
        let saved = saved(input, name);
        let running = running(input, name);
        if saved.is_none() && running.is_none() && input.capability.supported {
            // Neither saved nor possibly running: declarative no-op. Without
            // support the change is still emitted so it surfaces as unsupported.
            continue;
        }
        let known = saved.or(match running {
            Some(RunningSecret::Known(settings)) => Some(settings),
            Some(RunningSecret::Unknown) | None => None,
        });
        let change = SecretChangeKind::Removed;
        let disposition = secret_disposition(input, change, false);
        push_live_secret_warning(input, change, false, disposition, &mut output.warnings);
        output
            .changes
            .push(PlannedChange::Secret(SecretPlannedChange {
                field: SECRET_FIELD.to_string(),
                name: name.clone(),
                change,
                before_ref: Some(
                    known
                        .map(|secret| secret.placeholder.clone())
                        .unwrap_or_else(|| default_placeholder(name)),
                ),
                after_ref: None,
                disposition,
                allow_hosts: known
                    .map(|secret| secret.allowed_hosts.clone())
                    .unwrap_or_default(),
                reason: secret_reason(input, change, false, disposition),
            }));
        insert_aspects(output, name, [SecretAspect::Removed]);
    }
}

/// Reject patches that can never apply: a nameless spec, value plus source,
/// store sources, a new secret without material or hosts, a name that is
/// both configured and removed or stated twice, and a shared placeholder.
/// A name stated twice gets only that conflict. Messages carry names and
/// references, never values. Without support the whole secret surface is
/// already unsupported, so no per-entry checks run.
fn push_secret_conflicts(input: &SecretPlanInput<'_>, conflicts: &mut Vec<ModificationConflict>) {
    if !input.capability.supported {
        return;
    }

    let configured_twice: Vec<&str> = repeated(input.secrets.iter().map(|spec| spec.name.as_str()))
        .into_iter()
        .filter(|name| !name.is_empty())
        .collect();
    let removed_twice = repeated(input.secrets_remove.iter().map(String::as_str));

    let mut conflict = |message: String| {
        conflicts.push(ModificationConflict {
            field: SECRET_FIELD.to_string(),
            message,
        });
    };

    for spec in input.secrets {
        let name = &spec.name;
        if name.is_empty() {
            conflict("secret spec needs a name; call .env(..) in the secret closure".to_string());
            continue;
        }
        if configured_twice.contains(&name.as_str()) || removed_twice.contains(&name.as_str()) {
            continue;
        }

        if matches!(spec.material, DesiredMaterial::ValueAndSource(_)) {
            conflict(format!(
                "secret {name}: value and source are mutually exclusive"
            ));
        }
        if matches!(spec.material.source(), Some(SecretSource::Store { .. })) {
            conflict(format!(
                "secret {name}: store-backed secret sources are not supported yet"
            ));
        }

        if saved(input, name).is_none() {
            if !spec.material.carries_material() {
                conflict(format!(
                    "secret {name} needs a host-side source or value to add"
                ));
            }
            if spec.allowed_hosts.is_empty() {
                conflict(format!("secret {name} needs at least one allowed host"));
            }
        }

        if input.secrets_remove.contains(name) {
            conflict(format!(
                "secret {name} is both configured and removed in the same modification"
            ));
        }
    }

    for name in &configured_twice {
        conflict(format!(
            "secret {name} is configured more than once in the same modification"
        ));
    }
    for name in &removed_twice {
        conflict(format!(
            "secret {name} is removed more than once in the same modification"
        ));
    }

    push_shared_placeholder_conflicts(input, &configured_twice, &mut conflict);
}

/// Two secrets with one placeholder cannot be told apart in a request. Refuse
/// a patch that brings a secret into such a pair, by adding it or by changing
/// its placeholder; a pair the patch does not touch stays modifiable. A name
/// configured twice is already refused, so it is left out whether saved or added.
fn push_shared_placeholder_conflicts(
    input: &SecretPlanInput<'_>,
    configured_twice: &[&str],
    conflict: &mut impl FnMut(String),
) {
    let removed = |name: &str| input.secrets_remove.iter().any(|removed| removed == name);
    let spec_for = |name: &str| {
        input
            .secrets
            .iter()
            .find(|spec| spec.name == name && !configured_twice.contains(&name))
    };

    // Every placeholder after the patch, and whether this patch set it.
    let mut placeholders: Vec<(&str, String, bool)> = Vec::new();
    for saved in input
        .saved
        .iter()
        .filter(|saved| !removed(&saved.name) && !configured_twice.contains(&saved.name.as_str()))
    {
        let spec = spec_for(&saved.name);
        let placeholder = spec
            .and_then(|spec| spec.placeholder.clone())
            .unwrap_or_else(|| saved.placeholder.clone());
        let touched = spec.is_some_and(|spec| placeholder_changes(spec, Some(saved), None));
        placeholders.push((&saved.name, placeholder, touched));
    }
    for spec in input.secrets {
        let name = spec.name.as_str();
        if name.is_empty()
            || removed(name)
            || configured_twice.contains(&name)
            || placeholders.iter().any(|(listed, ..)| *listed == name)
        {
            continue;
        }
        let placeholder = spec
            .placeholder
            .clone()
            .unwrap_or_else(|| default_placeholder(name));
        placeholders.push((name, placeholder, true));
    }

    for (index, (first, placeholder, first_touched)) in placeholders.iter().enumerate() {
        for (second, other, second_touched) in &placeholders[index + 1..] {
            if placeholder == other && (*first_touched || *second_touched) {
                conflict(format!(
                    "secrets {first} and {second} use the same placeholder {placeholder}; \
                     each secret needs its own"
                ));
            }
        }
    }
}

/// Names that occur more than once, in the order they first repeat.
fn repeated<'a>(names: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = BTreeSet::new();
    let mut repeated = Vec::new();
    for name in names {
        if !seen.insert(name) && !repeated.contains(&name) {
            repeated.push(name);
        }
    }
    repeated
}

/// Infer what a declarative secret spec changes. `None` means the spec
/// already matches the target state.
fn infer_secret_change(
    spec: &DesiredSecret,
    saved: Option<&SecretSettings>,
    placeholder_changed: bool,
    hosts_changed: bool,
) -> Option<SecretChangeKind> {
    if saved.is_none() {
        return Some(SecretChangeKind::Added);
    }
    if spec.material.carries_material() {
        return Some(SecretChangeKind::Rotated);
    }
    if placeholder_changed {
        return Some(SecretChangeKind::PlaceholderUpdated);
    }
    if hosts_changed {
        return Some(SecretChangeKind::HostsUpdated);
    }
    None
}

/// Whether the spec asks for a guest-visible placeholder different from the
/// saved one or the running one. Placeholder changes cannot reach running
/// processes, so they disqualify an otherwise live-capable change.
fn placeholder_changes(
    spec: &DesiredSecret,
    saved: Option<&SecretSettings>,
    running: Option<&RunningSecret>,
) -> bool {
    spec.placeholder.as_deref().is_some_and(|placeholder| {
        saved.is_none()
            || field_changes(
                placeholder,
                |settings| settings.placeholder.as_str(),
                saved,
                running,
            )
    })
}

/// Whether any supplied policy field changes. Omitted options and empty host
/// lists leave an existing policy unchanged, matching persistence.
fn policy_changes(
    spec: &DesiredSecret,
    saved: Option<&SecretSettings>,
    running: Option<&RunningSecret>,
) -> bool {
    spec.substitution.as_ref().is_some_and(|substitution| {
        field_changes(
            substitution_key(substitution),
            |settings| substitution_key(&settings.substitution),
            saved,
            running,
        )
    }) || (!spec.passthrough_hosts.is_empty()
        && field_changes(
            spec.passthrough_hosts.as_slice(),
            |settings| settings.passthrough_hosts.as_slice(),
            saved,
            running,
        ))
        || spec.violation_action.as_ref().is_some_and(|action| {
            field_changes(
                Some(action),
                |settings| settings.violation_action.as_ref(),
                saved,
                running,
            )
        })
        || spec.require_tls_identity.is_some_and(|required| {
            field_changes(
                required,
                |settings| settings.require_tls_identity,
                saved,
                running,
            )
        })
}

/// A supplied field is a change if it differs from the saved settings, or
/// from the running sandbox's settings, or the running sandbox's are unknown.
fn field_changes<'a, T: PartialEq>(
    desired: T,
    field: impl Fn(&'a SecretSettings) -> T,
    saved: Option<&'a SecretSettings>,
    running: Option<&'a RunningSecret>,
) -> bool {
    saved.is_some_and(|settings| field(settings) != desired)
        || match running {
            Some(RunningSecret::Unknown) => true,
            Some(RunningSecret::Known(settings)) => field(settings) != desired,
            None => false,
        }
}

fn substitution_key(substitution: &SecretSubstitution) -> (bool, &[String], bool, bool) {
    (
        substitution.headers,
        substitution.header_fields.as_slice(),
        substitution.query,
        substitution.body,
    )
}

fn saved<'a>(input: &SecretPlanInput<'a>, name: &str) -> Option<&'a SecretSettings> {
    input.saved.iter().find(|secret| secret.name == name)
}

/// The running sandbox's view of `name`; `None` unless the sandbox runs and
/// the backend's view names the secret.
fn running<'a>(input: &SecretPlanInput<'a>, name: &str) -> Option<&'a RunningSecret> {
    if input.status != SecretPlanStatus::Running {
        return None;
    }
    input.running?.get(name)
}

fn insert_aspects(
    output: &mut SecretPlanOutput,
    name: &str,
    aspects: impl IntoIterator<Item = SecretAspect>,
) {
    output
        .aspects
        .entry(name.to_string())
        .or_default()
        .extend(aspects);
}

/// Whether the backend delivers this kind of change to a running sandbox.
fn live_capable(capability: SecretPlanCapability, change: SecretChangeKind) -> bool {
    match change {
        SecretChangeKind::Rotated | SecretChangeKind::HostsUpdated | SecretChangeKind::Removed => {
            capability.live
        }
        SecretChangeKind::Added
        | SecretChangeKind::Renamed
        | SecretChangeKind::PlaceholderUpdated => false,
    }
}

fn secret_disposition(
    input: &SecretPlanInput<'_>,
    change: SecretChangeKind,
    placeholder_changed: bool,
) -> ModificationDisposition {
    // Without support there is no secrets layer to persist into or
    // reconfigure, so every secret change is unsupported.
    if !input.capability.supported {
        return ModificationDisposition::Unsupported;
    }
    if input.policy == ModificationPolicy::NextStart {
        return ModificationDisposition::NextStart;
    }
    match input.status {
        SecretPlanStatus::Stopped => ModificationDisposition::NextStart,
        SecretPlanStatus::Transitional { .. } => ModificationDisposition::Unsupported,
        // A rotate that also changes the guest-visible placeholder cannot
        // apply live: the new placeholder never reaches running processes.
        SecretPlanStatus::Running
            if live_capable(input.capability, change) && !placeholder_changed =>
        {
            ModificationDisposition::Live
        }
        SecretPlanStatus::Running => ModificationDisposition::RequiresRestart,
    }
}

fn secret_reason(
    input: &SecretPlanInput<'_>,
    change: SecretChangeKind,
    placeholder_changed: bool,
    disposition: ModificationDisposition,
) -> Option<String> {
    if !input.capability.supported {
        return Some(SECRETS_UNSUPPORTED.to_string());
    }
    match disposition {
        ModificationDisposition::RequiresRestart if input.status == SecretPlanStatus::Running => {
            if placeholder_changed
                || matches!(
                    change,
                    SecretChangeKind::Added
                        | SecretChangeKind::Renamed
                        | SecretChangeKind::PlaceholderUpdated
                )
            {
                Some(SECRET_PLACEHOLDER_REQUIRES_RESTART.to_string())
            } else {
                Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string())
            }
        }
        ModificationDisposition::Unsupported => unsupported_reason(input.status),
        _ => None,
    }
}

/// Warn when a live-capable secret change falls back to restart-required
/// only because the backend cannot deliver it live.
fn push_live_secret_warning(
    input: &SecretPlanInput<'_>,
    change: SecretChangeKind,
    placeholder_changed: bool,
    disposition: ModificationDisposition,
    warnings: &mut Vec<ModificationWarning>,
) {
    if matches!(disposition, ModificationDisposition::RequiresRestart)
        && input.status == SecretPlanStatus::Running
        && !placeholder_changed
        && matches!(
            change,
            SecretChangeKind::Rotated | SecretChangeKind::Removed | SecretChangeKind::HostsUpdated
        )
        && !live_capable(input.capability, change)
    {
        warnings.push(ModificationWarning {
            field: SECRET_FIELD.to_string(),
            message: LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string(),
        });
    }
}

fn config_disposition(
    status: SecretPlanStatus,
    policy: ModificationPolicy,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart {
        return ModificationDisposition::NextStart;
    }
    match status {
        SecretPlanStatus::Stopped => ModificationDisposition::NextStart,
        SecretPlanStatus::Transitional { .. } => ModificationDisposition::Unsupported,
        SecretPlanStatus::Running => ModificationDisposition::RequiresRestart,
    }
}

fn config_reason(
    status: SecretPlanStatus,
    policy: ModificationPolicy,
    running_reason: &str,
) -> Option<String> {
    match config_disposition(status, policy) {
        ModificationDisposition::RequiresRestart => Some(running_reason.to_string()),
        ModificationDisposition::Unsupported => unsupported_reason(status),
        _ => None,
    }
}

fn unsupported_reason(status: SecretPlanStatus) -> Option<String> {
    match status {
        SecretPlanStatus::Transitional { name } => {
            Some(format!("cannot modify while sandbox is {name}"))
        }
        SecretPlanStatus::Stopped | SecretPlanStatus::Running => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SecretViolationAction;

    const LOCAL: SecretPlanCapability = SecretPlanCapability {
        supported: true,
        live: true,
        restart: true,
    };
    const CLOUD: SecretPlanCapability = SecretPlanCapability {
        restart: false,
        ..LOCAL
    };

    fn settings(name: &str, hosts: &[&str]) -> SecretSettings {
        SecretSettings {
            name: name.into(),
            placeholder: default_placeholder(name),
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: true,
        }
    }

    fn desired(name: &str, hosts: &[&str]) -> DesiredSecret {
        DesiredSecret {
            name: name.into(),
            material: DesiredMaterial::Keep,
            placeholder: None,
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            substitution: None,
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: None,
        }
    }

    fn rotation(name: &str, hosts: &[&str]) -> DesiredSecret {
        DesiredSecret {
            material: DesiredMaterial::Value,
            ..desired(name, hosts)
        }
    }

    fn known(settings: &[SecretSettings]) -> BTreeMap<String, RunningSecret> {
        settings
            .iter()
            .map(|secret| (secret.name.clone(), RunningSecret::Known(secret.clone())))
            .collect()
    }

    fn unknown(names: &[&str]) -> BTreeMap<String, RunningSecret> {
        names
            .iter()
            .map(|name| (name.to_string(), RunningSecret::Unknown))
            .collect()
    }

    struct Case<'a> {
        status: SecretPlanStatus,
        policy: ModificationPolicy,
        capability: SecretPlanCapability,
        saved: &'a [SecretSettings],
        running: Option<&'a BTreeMap<String, RunningSecret>>,
        secrets: &'a [DesiredSecret],
        secrets_remove: &'a [String],
    }

    impl Case<'_> {
        fn plan(&self) -> SecretPlanOutput {
            plan(&SecretPlanInput {
                status: self.status,
                policy: self.policy,
                capability: self.capability,
                saved: self.saved,
                running: self.running,
                secrets: self.secrets,
                secrets_remove: self.secrets_remove,
            })
        }
    }

    fn running<'a>(
        saved: &'a [SecretSettings],
        running_secrets: Option<&'a BTreeMap<String, RunningSecret>>,
        secrets: &'a [DesiredSecret],
        secrets_remove: &'a [String],
    ) -> Case<'a> {
        Case {
            status: SecretPlanStatus::Running,
            policy: ModificationPolicy::NoRestart,
            capability: CLOUD,
            saved,
            running: running_secrets,
            secrets,
            secrets_remove,
        }
    }

    fn json(changes: &[PlannedChange]) -> serde_json::Value {
        serde_json::to_value(changes).unwrap()
    }

    fn secret_entries(output: &SecretPlanOutput) -> Vec<&SecretPlannedChange> {
        output
            .changes
            .iter()
            .filter_map(|change| match change {
                PlannedChange::Secret(change) => Some(change),
                PlannedChange::Config(_) => None,
            })
            .collect()
    }

    fn the_plan(output: &SecretPlanOutput, policy: ModificationPolicy) -> SandboxModificationPlan {
        SandboxModificationPlan {
            sandbox: "api".into(),
            status: "running".into(),
            applied: false,
            policy,
            changes: output.changes.clone(),
            conflicts: output.conflicts.clone(),
            warnings: output.warnings.clone(),
            resize_status: Vec::new(),
        }
    }

    #[test]
    fn field_changes_table() {
        let equal = settings("API_KEY", &["a.test"]);
        let different = settings("API_KEY", &["b.test"]);
        let known_equal = RunningSecret::Known(equal.clone());
        let known_different = RunningSecret::Known(different.clone());
        let desired = ["a.test".to_string()];
        for (saved, running, expected) in [
            (None, None, false),
            (None, Some(&known_equal), false),
            (None, Some(&known_different), true),
            (None, Some(&RunningSecret::Unknown), true),
            (Some(&equal), None, false),
            (Some(&equal), Some(&known_equal), false),
            (Some(&equal), Some(&known_different), true),
            (Some(&equal), Some(&RunningSecret::Unknown), true),
            (Some(&different), None, true),
            (Some(&different), Some(&known_equal), true),
            (Some(&different), Some(&known_different), true),
            (Some(&different), Some(&RunningSecret::Unknown), true),
        ] {
            assert_eq!(
                field_changes(
                    desired.as_slice(),
                    |settings| settings.allowed_hosts.as_slice(),
                    saved,
                    running,
                ),
                expected,
                "saved {:?}, running {running:?}",
                saved.map(|settings| &settings.allowed_hosts),
            );
        }
    }

    #[test]
    fn host_order_counts() {
        let saved = [settings("API_KEY", &["a.test", "b.test"])];
        let secrets = [desired("API_KEY", &["b.test", "a.test"])];
        let output = running(&saved, None, &secrets, &[]).plan();
        assert_eq!(
            secret_entries(&output)[0].change,
            SecretChangeKind::HostsUpdated
        );
    }

    #[test]
    fn unknown_running_plans_hosts_change() {
        let saved = [settings("API_KEY", &["a.test"])];
        let running_secrets = unknown(&["API_KEY"]);
        let secrets = [desired("API_KEY", &["a.test"])];
        let output = running(&saved, Some(&running_secrets), &secrets, &[]).plan();
        let entries = secret_entries(&output);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].change, SecretChangeKind::HostsUpdated);
        assert_eq!(entries[0].disposition, ModificationDisposition::Live);
        assert_eq!(entries[0].allow_hosts, ["a.test"]);

        // Only a running sandbox has a running view.
        for status in [
            SecretPlanStatus::Stopped,
            SecretPlanStatus::Transitional { name: "starting" },
        ] {
            let output = Case {
                status,
                ..running(&saved, Some(&running_secrets), &secrets, &[])
            }
            .plan();
            assert!(output.changes.is_empty());
        }
    }

    #[test]
    fn unknown_running_policy_change_requires_restart() {
        let saved = [settings("API_KEY", &["a.test"])];
        let running_secrets = unknown(&["API_KEY"]);
        let secrets = [DesiredSecret {
            require_tls_identity: Some(true),
            ..desired("API_KEY", &[])
        }];
        let output = running(&saved, Some(&running_secrets), &secrets, &[]).plan();
        let [PlannedChange::Config(change)] = output.changes.as_slice() else {
            panic!("expected one policy change, got {:?}", output.changes);
        };
        assert_eq!(change.field, secret_policy_field("API_KEY"));
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert_eq!(
            change.reason.as_deref(),
            Some(SECRET_POLICY_REQUIRES_RESTART)
        );

        // The same supplied rule, saved and running alike, is no change.
        let output = running(&saved, Some(&known(&saved)), &secrets, &[]).plan();
        assert!(output.changes.is_empty());
    }

    #[test]
    fn placeholder_saved_but_not_running_requires_restart() {
        let saved = [SecretSettings {
            placeholder: "$NEW".into(),
            ..settings("API_KEY", &["b.test"])
        }];
        let running_secrets = known(&[settings("API_KEY", &["a.test"])]);
        let replay = [DesiredSecret {
            placeholder: Some("$NEW".into()),
            ..desired("API_KEY", &["b.test"])
        }];
        for policy in [ModificationPolicy::NoRestart, ModificationPolicy::Restart] {
            let output = Case {
                capability: LOCAL,
                policy,
                ..running(&saved, Some(&running_secrets), &replay, &[])
            }
            .plan();
            let entries = secret_entries(&output);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].change, SecretChangeKind::PlaceholderUpdated);
            assert_eq!(
                entries[0].disposition,
                ModificationDisposition::RequiresRestart
            );
            assert!(output.aspects["API_KEY"].contains(&SecretAspect::PlaceholderUpdated));
        }

        // A rotation that restates the placeholder does not go live either.
        let rotate = [DesiredSecret {
            placeholder: Some("$NEW".into()),
            ..rotation("API_KEY", &[])
        }];
        let output = running(&saved, Some(&running_secrets), &rotate, &[]).plan();
        assert_eq!(
            secret_entries(&output)[0].disposition,
            ModificationDisposition::RequiresRestart
        );

        // An unknown run cannot be shown to have the placeholder.
        let output = running(&saved, Some(&unknown(&["API_KEY"])), &replay, &[]).plan();
        assert_eq!(
            secret_entries(&output)[0].disposition,
            ModificationDisposition::RequiresRestart
        );

        // A run that has the placeholder is no change, and an omitted
        // placeholder is never a placeholder change.
        let output = running(&saved, Some(&known(&saved)), &replay, &[]).plan();
        assert!(output.changes.is_empty());
        let hosts_only = [desired("API_KEY", &["b.test"])];
        let output = running(&saved, Some(&running_secrets), &hosts_only, &[]).plan();
        let entries = secret_entries(&output);
        assert_eq!(entries[0].change, SecretChangeKind::HostsUpdated);
        assert_eq!(entries[0].disposition, ModificationDisposition::Live);
    }

    #[test]
    fn held_removal_is_planned_live() {
        let held = settings("API_KEY", &["a.test"]);
        let removals = ["API_KEY".to_string()];
        for running_secrets in [known(std::slice::from_ref(&held)), unknown(&["API_KEY"])] {
            let output = running(&[], Some(&running_secrets), &[], &removals).plan();
            let entries = secret_entries(&output);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].change, SecretChangeKind::Removed);
            assert_eq!(entries[0].disposition, ModificationDisposition::Live);
            assert_eq!(
                entries[0].before_ref.as_deref(),
                Some(held.placeholder.as_str())
            );
            assert_eq!(output.aspects["API_KEY"], [SecretAspect::Removed].into());
        }

        // Neither saved nor running: still a no-op.
        let output = running(&[], Some(&BTreeMap::new()), &[], &removals).plan();
        assert!(output.changes.is_empty());
        assert!(output.aspects.is_empty());
    }

    #[test]
    fn saved_and_running_equal_plan_as_today() {
        let saved = [settings("API_KEY", &["a.test"])];
        let running_secrets = known(&saved);
        let removals = ["MISSING".to_string()];
        for (secrets, expected) in [
            (vec![desired("API_KEY", &["a.test"])], None),
            (
                vec![desired("API_KEY", &["b.test"])],
                Some(SecretChangeKind::HostsUpdated),
            ),
            (
                vec![rotation("API_KEY", &[])],
                Some(SecretChangeKind::Rotated),
            ),
        ] {
            let with_running = running(&saved, Some(&running_secrets), &secrets, &removals).plan();
            let without_running = running(&saved, None, &secrets, &removals).plan();
            assert_eq!(
                json(&with_running.changes),
                json(&without_running.changes),
                "an equal running view changes nothing"
            );
            assert_eq!(
                secret_entries(&with_running)
                    .first()
                    .map(|entry| entry.change),
                expected
            );
        }
    }

    #[test]
    fn aspects() {
        let saved = [settings("API_KEY", &["a.test"])];
        let same_running = known(&saved);
        let unknown_running = unknown(&["API_KEY"]);
        let removals = ["API_KEY".to_string()];
        let cases: Vec<(Vec<DesiredSecret>, &[String], _, &[SecretAspect])> = vec![
            (
                vec![rotation("API_KEY", &["b.test"])],
                &[],
                None,
                &[SecretAspect::Rotated, SecretAspect::HostsUpdated],
            ),
            (
                vec![DesiredSecret {
                    placeholder: Some("$OTHER".into()),
                    ..rotation("API_KEY", &[])
                }],
                &[],
                None,
                &[SecretAspect::Rotated, SecretAspect::PlaceholderUpdated],
            ),
            (
                vec![DesiredSecret {
                    violation_action: Some(SecretViolationAction::Block),
                    ..rotation("API_KEY", &[])
                }],
                &[],
                None,
                &[SecretAspect::Rotated, SecretAspect::PolicyUpdated],
            ),
            (
                vec![rotation("API_KEY", &["a.test"])],
                &[],
                Some(&same_running),
                &[SecretAspect::Rotated],
            ),
            (
                vec![desired("API_KEY", &["a.test"])],
                &[],
                Some(&unknown_running),
                &[SecretAspect::HostsUpdated],
            ),
            (
                vec![rotation("NEW_KEY", &["a.test"])],
                &[],
                None,
                &[SecretAspect::Added],
            ),
            (Vec::new(), &removals, None, &[SecretAspect::Removed]),
        ];
        for (secrets, secrets_remove, running_secrets, expected) in cases {
            let output = running(&saved, running_secrets, &secrets, secrets_remove).plan();
            let name = secrets
                .first()
                .map_or("API_KEY", |secret| secret.name.as_str());
            assert_eq!(output.aspects.len(), 1);
            assert_eq!(
                output.aspects[name],
                expected.iter().copied().collect::<BTreeSet<_>>(),
                "{secrets:?}"
            );
            // The public plan keeps one kind per entry.
            assert_eq!(secret_entries(&output).len(), 1);
        }
    }

    #[test]
    fn planner_parity_table() {
        let saved = [
            settings("API_KEY", &["a.test"]),
            settings("OLD_KEY", &["a.test"]),
        ];
        let running_secrets = known(&saved);
        let removals = ["OLD_KEY".to_string()];
        let patches: Vec<(Vec<DesiredSecret>, &[String])> = vec![
            (vec![rotation("API_KEY", &[])], &[]),
            (vec![rotation("API_KEY", &["b.test"])], &[]),
            (vec![desired("API_KEY", &["b.test"])], &[]),
            (
                vec![DesiredSecret {
                    placeholder: Some("$OTHER".into()),
                    ..desired("API_KEY", &[])
                }],
                &[],
            ),
            (
                vec![DesiredSecret {
                    require_tls_identity: Some(false),
                    ..desired("API_KEY", &[])
                }],
                &[],
            ),
            (vec![rotation("NEW_KEY", &["a.test"])], &[]),
            (vec![rotation("NEW_KEY", &[])], &[]),
            (Vec::new(), &removals),
        ];
        let statuses = [
            SecretPlanStatus::Stopped,
            SecretPlanStatus::Running,
            SecretPlanStatus::Transitional { name: "paused" },
        ];
        let policies = [
            ModificationPolicy::NoRestart,
            ModificationPolicy::NextStart,
            ModificationPolicy::Restart,
        ];
        let mut restart_refusals = 0;
        for (secrets, secrets_remove) in &patches {
            for status in statuses {
                for policy in policies {
                    for running_secrets in [None, Some(&running_secrets)] {
                        let case = |capability| Case {
                            status,
                            policy,
                            capability,
                            saved: &saved,
                            running: running_secrets,
                            secrets,
                            secrets_remove,
                        };
                        let local = case(LOCAL).plan();
                        let cloud = case(CLOUD).plan();
                        assert_eq!(json(&local.changes), json(&cloud.changes));
                        assert_eq!(local.conflicts, cloud.conflicts);
                        assert_eq!(local.warnings, cloud.warnings);
                        assert_eq!(local.aspects, cloud.aspects);

                        let local_refusal = refusal_reason(&the_plan(&local, policy), LOCAL);
                        let cloud_refusal = refusal_reason(&the_plan(&cloud, policy), CLOUD);
                        let restart_entry = cloud.conflicts.is_empty()
                            && policy == ModificationPolicy::Restart
                            && cloud.changes.iter().any(|change| {
                                matches!(
                                    change,
                                    PlannedChange::Secret(SecretPlannedChange {
                                        disposition: ModificationDisposition::RequiresRestart,
                                        ..
                                    }) | PlannedChange::Config(ConfigPlannedChange {
                                        disposition: ModificationDisposition::RequiresRestart,
                                        ..
                                    })
                                )
                            })
                            && !cloud.changes.iter().any(|change| {
                                matches!(
                                    change,
                                    PlannedChange::Secret(SecretPlannedChange {
                                        disposition: ModificationDisposition::Unsupported,
                                        ..
                                    }) | PlannedChange::Config(ConfigPlannedChange {
                                        disposition: ModificationDisposition::Unsupported,
                                        ..
                                    })
                                )
                            });
                        if restart_entry {
                            restart_refusals += 1;
                            assert_eq!(local_refusal, None);
                            let message = cloud_refusal.expect("cloud refuses a restart");
                            assert!(
                                message.ends_with(
                                    "requires restart, and this sandbox cannot be restarted \
                                     by modify; use next_start, then stop and start it"
                                ),
                                "{message}"
                            );
                        } else {
                            assert_eq!(local_refusal, cloud_refusal);
                        }
                    }
                }
            }
        }
        assert!(restart_refusals > 0);
    }

    #[test]
    fn restart_refusal_names_the_secret() {
        let saved = [settings("API_KEY", &["a.test"])];
        let secrets = [DesiredSecret {
            placeholder: Some("$OTHER".into()),
            ..desired("API_KEY", &[])
        }];
        let output = Case {
            policy: ModificationPolicy::Restart,
            ..running(&saved, None, &secrets, &[])
        }
        .plan();
        assert_eq!(
            refusal_reason(&the_plan(&output, ModificationPolicy::Restart), CLOUD).as_deref(),
            Some(
                "cannot apply modification: secret API_KEY requires restart, and this sandbox \
                 cannot be restarted by modify; use next_start, then stop and start it"
            )
        );
        assert_eq!(
            refusal_reason(&the_plan(&output, ModificationPolicy::Restart), LOCAL),
            None
        );
    }

    #[test]
    fn live_flag_covers_every_live_change_kind() {
        let saved = [
            settings("API_KEY", &["a.test"]),
            settings("HOST_KEY", &["a.test"]),
            settings("OLD_KEY", &["a.test"]),
        ];
        let secrets = [rotation("API_KEY", &[]), desired("HOST_KEY", &["b.test"])];
        let removals = ["OLD_KEY".to_string()];
        for (live, expected, warnings) in [
            (true, ModificationDisposition::Live, 0),
            (false, ModificationDisposition::RequiresRestart, 3),
        ] {
            let output = Case {
                capability: SecretPlanCapability { live, ..CLOUD },
                ..running(&saved, None, &secrets, &removals)
            }
            .plan();
            let dispositions: Vec<_> = secret_entries(&output)
                .iter()
                .map(|entry| entry.disposition)
                .collect();
            assert_eq!(dispositions, [expected; 3]);
            assert_eq!(output.warnings.len(), warnings);
        }
    }

    #[test]
    fn unsupported_backend_plans_every_entry_unsupported() {
        let removals = ["MISSING".to_string()];
        let secrets = [rotation("NEW_KEY", &[])];
        let output = Case {
            capability: SecretPlanCapability {
                supported: false,
                ..LOCAL
            },
            ..running(&[], None, &secrets, &removals)
        }
        .plan();
        assert!(output.conflicts.is_empty());
        let entries = secret_entries(&output);
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(entry.disposition, ModificationDisposition::Unsupported);
            assert_eq!(entry.reason.as_deref(), Some(SECRETS_UNSUPPORTED));
        }
    }

    fn conflict_messages(output: &SecretPlanOutput) -> Vec<&str> {
        output
            .conflicts
            .iter()
            .map(|conflict| conflict.message.as_str())
            .collect()
    }

    #[test]
    fn duplicate_configured_name_is_refused() {
        let saved = [settings("API_KEY", &["a.test"])];
        let secrets = [
            rotation("API_KEY", &[]),
            rotation("API_KEY", &["b.test"]),
            rotation("API_KEY", &["c.test"]),
        ];
        let output = running(&saved, None, &secrets, &[]).plan();
        assert_eq!(
            conflict_messages(&output),
            ["secret API_KEY is configured more than once in the same modification"]
        );
        assert!(output.changes.is_empty());
        assert!(output.aspects.is_empty());
        assert_eq!(
            refusal_reason(&the_plan(&output, ModificationPolicy::NoRestart), CLOUD).as_deref(),
            Some(
                "cannot apply modification: secret API_KEY is configured more than once in \
                 the same modification"
            )
        );
    }

    #[test]
    fn invalid_duplicate_specs_get_only_the_duplicate_conflict() {
        let saved = [settings("OTHER_KEY", &["a.test"])];
        let removals = ["OLD_KEY".to_string(), "OLD_KEY".to_string()];
        let secrets = [
            desired("API_KEY", &[]),
            DesiredSecret {
                placeholder: Some(default_placeholder("OTHER_KEY")),
                material: DesiredMaterial::ValueAndSource(SecretSource::Store {
                    reference: "vault://api".into(),
                }),
                ..desired("API_KEY", &[])
            },
            desired("OLD_KEY", &[]),
        ];
        let output = running(&saved, None, &secrets, &removals).plan();
        assert_eq!(
            conflict_messages(&output),
            [
                "secret API_KEY is configured more than once in the same modification",
                "secret OLD_KEY is removed more than once in the same modification",
            ]
        );
        assert!(output.changes.is_empty());

        let secrets = [desired("API_KEY", &[]), desired("API_KEY", &[])];
        let output = running(&[], None, &secrets, &[]).plan();
        assert_eq!(
            conflict_messages(&output),
            ["secret API_KEY is configured more than once in the same modification"]
        );
        assert_eq!(
            refusal_reason(&the_plan(&output, ModificationPolicy::NoRestart), CLOUD).as_deref(),
            Some(
                "cannot apply modification: secret API_KEY is configured more than once in \
                 the same modification"
            )
        );
    }

    #[test]
    fn duplicated_saved_name_is_left_out_of_the_placeholder_check() {
        let saved = [settings("API_KEY", &["a.test"])];
        let secrets = [
            rotation("API_KEY", &[]),
            rotation("API_KEY", &["b.test"]),
            DesiredSecret {
                placeholder: Some(default_placeholder("API_KEY")),
                ..rotation("NEW_KEY", &["a.test"])
            },
        ];
        let output = running(&saved, None, &secrets, &[]).plan();
        assert_eq!(
            conflict_messages(&output),
            ["secret API_KEY is configured more than once in the same modification"]
        );
    }

    #[test]
    fn duplicate_removed_name_is_refused() {
        let saved = [
            settings("API_KEY", &["a.test"]),
            settings("OLD_KEY", &["a.test"]),
        ];
        let removals = [
            "API_KEY".to_string(),
            "OLD_KEY".to_string(),
            "API_KEY".to_string(),
        ];
        let output = running(&saved, None, &[], &removals).plan();
        assert_eq!(
            conflict_messages(&output),
            ["secret API_KEY is removed more than once in the same modification"]
        );
        let entries = secret_entries(&output);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "OLD_KEY");
        assert!(refusal_reason(&the_plan(&output, ModificationPolicy::NoRestart), LOCAL).is_some());
    }

    #[test]
    fn shared_placeholder_is_refused_when_touched() {
        let saved = [
            settings("API_KEY", &["a.test"]),
            settings("OTHER_KEY", &["a.test"]),
        ];
        let removals = ["API_KEY".to_string()];
        let cases: Vec<(Vec<DesiredSecret>, &[String], Option<&str>)> = vec![
            // An add takes an existing placeholder.
            (
                vec![DesiredSecret {
                    placeholder: Some("$MSB_API_KEY".into()),
                    ..rotation("NEW_KEY", &["a.test"])
                }],
                &[],
                Some(
                    "secrets API_KEY and NEW_KEY use the same placeholder $MSB_API_KEY; each \
                     secret needs its own",
                ),
            ),
            // An existing secret moves onto another's placeholder.
            (
                vec![DesiredSecret {
                    placeholder: Some("$MSB_API_KEY".into()),
                    ..desired("OTHER_KEY", &[])
                }],
                &[],
                Some(
                    "secrets API_KEY and OTHER_KEY use the same placeholder $MSB_API_KEY; each \
                     secret needs its own",
                ),
            ),
            // Two adds take one placeholder.
            (
                vec![
                    DesiredSecret {
                        placeholder: Some("$SHARED".into()),
                        ..rotation("NEW_KEY", &["a.test"])
                    },
                    DesiredSecret {
                        placeholder: Some("$SHARED".into()),
                        ..rotation("NEXT_KEY", &["a.test"])
                    },
                ],
                &[],
                Some(
                    "secrets NEW_KEY and NEXT_KEY use the same placeholder $SHARED; each secret \
                     needs its own",
                ),
            ),
            // The placeholder is free once its secret is removed.
            (
                vec![DesiredSecret {
                    placeholder: Some("$MSB_API_KEY".into()),
                    ..rotation("NEW_KEY", &["a.test"])
                }],
                &removals,
                None,
            ),
        ];
        for (secrets, secrets_remove, expected) in cases {
            let output = running(&saved, None, &secrets, secrets_remove).plan();
            assert_eq!(
                conflict_messages(&output),
                expected.into_iter().collect::<Vec<_>>(),
                "{secrets:?}"
            );
        }
    }

    #[test]
    fn existing_shared_placeholder_is_not_refused() {
        let shared = |name: &str| SecretSettings {
            placeholder: "$SHARED".into(),
            ..settings(name, &["a.test"])
        };
        let saved = [shared("API_KEY"), shared("OTHER_KEY")];
        let secrets = [
            rotation("API_KEY", &[]),
            DesiredSecret {
                placeholder: Some("$SHARED".into()),
                ..desired("OTHER_KEY", &["b.test"])
            },
        ];
        let output = running(&saved, None, &secrets, &[]).plan();
        assert!(output.conflicts.is_empty(), "{:?}", output.conflicts);
        let kinds: Vec<_> = secret_entries(&output)
            .iter()
            .map(|entry| entry.change)
            .collect();
        assert_eq!(
            kinds,
            [SecretChangeKind::Rotated, SecretChangeKind::HostsUpdated]
        );
    }

    #[test]
    fn secret_policy_field_round_trips() {
        assert_eq!(secret_policy_field("API_KEY"), "secret.API_KEY.policy");
        assert_eq!(
            secret_name_from_policy_field(&secret_policy_field("API_KEY")),
            Some("API_KEY")
        );
        for field in [
            "secret",
            "tls",
            "secret.API_KEY",
            "env.secret.API_KEY.policy",
        ] {
            assert_eq!(secret_name_from_policy_field(field), None);
        }
    }
}
