//! Host-only admission for commands that use deferred snapshot configuration.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::exec::ExecRequest;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Outstanding references in effective new-command defaults. Never contains a bound value.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredCommandBindings {
    /// Environment key to the logical binding it still needs.
    pub env: BTreeMap<String, String>,
    /// Logical bindings still needed to construct the saved entrypoint.
    pub entrypoint: BTreeSet<String>,
    /// Logical bindings still needed to construct the saved CMD.
    pub cmd: BTreeSet<String>,
}

/// Caller input before merging sandbox defaults. Values travel only in the ordinary exec body.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecBindingOverrides {
    /// Caller selected the entire program and argument vector for this invocation.
    pub explicit_argv: bool,
    /// Keys explicitly supplied for this invocation, including explicitly empty values.
    pub env_keys: BTreeSet<String>,
}

/// Negotiated exec payload. Released SDKs send the plain command without origin evidence.
#[derive(Serialize)]
pub struct BoundExecRequest<'a> {
    /// Guest exec fields.
    #[serde(flatten)]
    pub command: &'a ExecRequest,
    /// Host-only per-call evidence. The relay strips this before forwarding.
    pub binding_overrides: ExecBindingOverrides,
}

/// Partial decoder accepts legacy requests and never treats a merged value as explicit.
#[derive(Deserialize)]
pub struct ExecBindingDiscovery {
    /// Absent on a legacy request.
    pub binding_overrides: Option<ExecBindingOverrides>,
}

/// Relay-owned Ready extension. Older peers continue to decode their usual Ready.
#[derive(Serialize)]
pub struct ExecBindingAdvertisement<T> {
    /// Existing Ready fields for this particular connection.
    #[serde(flatten)]
    pub ready: T,
    /// Only version 1 supports per-command origin evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_exec_bindings: Option<u8>,
    /// Host boot that admits this proof. A detached job uses a second connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_boot_id: Option<String>,
}

/// Partial decoder for host capability discovery before sending any new fields.
#[derive(Deserialize)]
pub struct ExecBindingCapability {
    /// Absent or unknown versions select the original request.
    pub relay_exec_bindings: Option<u8>,
    /// Host boot that admits this proof. A detached job uses a second connection.
    pub binding_boot_id: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DeferredCommandBindings {
    /// Ordinary sandboxes do not need to decode or rewrite exec payloads.
    pub fn is_empty(&self) -> bool {
        self.env.is_empty() && self.entrypoint.is_empty() && self.cmd.is_empty()
    }

    /// Remove the host-only proof after admission. Keep guest fields added by future peers.
    pub fn admit_payload(&self, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut value = crate::wire::decode_value(bytes).map_err(|_| "invalid exec command")?;
        crate::wire::validate_record(&value).map_err(|_| "invalid exec command")?;
        let command = value
            .deserialized::<ExecRequest>()
            .map_err(|_| "invalid exec command")?;
        let proof = value
            .deserialized::<ExecBindingDiscovery>()
            .map_err(|_| "invalid exec binding evidence")?;
        self.check(&command, proof.binding_overrides.as_ref())?;
        let Value::Map(fields) = &mut value else {
            return Err("invalid exec command");
        };
        fields.retain(|(key, _)| key.as_text() != Some("binding_overrides"));
        let mut out = Vec::with_capacity(bytes.len());
        ciborium::into_writer(&value, &mut out).map_err(|_| "cannot encode admitted command")?;
        Ok(out)
    }

    /// Verify origin and actual wire inputs together, before a guest can see the command.
    pub fn check(
        &self,
        command: &ExecRequest,
        overrides: Option<&ExecBindingOverrides>,
    ) -> Result<(), &'static str> {
        if self.is_empty() {
            return Ok(());
        }
        let overrides = overrides.ok_or("this command needs a destination binding; supply the binding at restore or use an SDK that can send an explicit command override")?;
        if (!self.entrypoint.is_empty() || !self.cmd.is_empty()) && !overrides.explicit_argv {
            return Err(
                "this command needs a bound entrypoint or CMD, or an explicit replacement command",
            );
        }
        // An explicit-key list alone is insufficient. A second assignment could win in
        // the guest, and a missing assignment would silently drop the required variable.
        let mut supplied = BTreeSet::new();
        for assignment in &command.env {
            if let Some((key, value)) = assignment.split_once('=')
                && self.env.contains_key(key)
                && (value.contains('\0') || !supplied.insert(key))
            {
                return Err("invalid or duplicate environment assignment for a deferred binding");
            }
        }
        if self
            .env
            .keys()
            .any(|key| !overrides.env_keys.contains(key) || !supplied.contains(key.as_str()))
        {
            return Err(
                "this command needs a destination environment binding or an explicit override for each unresolved key",
            );
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_consumer_needs_its_own_override_even_when_the_logical_binding_is_shared() {
        let policy = DeferredCommandBindings {
            cmd: ["credential".into()].into(),
            env: [
                ("FIRST".into(), "credential".into()),
                ("SECOND".into(), "credential".into()),
            ]
            .into(),
            ..Default::default()
        };
        let mut command: ExecRequest = serde_json::from_value(serde_json::json!({
            "cmd":"echo", "env":["FIRST=", "SECOND=example"]
        }))
        .unwrap();
        let mut proof = ExecBindingOverrides {
            explicit_argv: true,
            env_keys: ["FIRST".into()].into(),
        };
        assert!(policy.check(&command, None).is_err());
        assert!(policy.check(&command, Some(&proof)).is_err());
        proof.env_keys.insert("SECOND".into());
        proof.explicit_argv = false;
        assert!(policy.check(&command, Some(&proof)).is_err());
        proof.explicit_argv = true;
        assert!(policy.check(&command, Some(&proof)).is_ok());
        command.env.push("SECOND=other".to_string());
        assert!(policy.check(&command, Some(&proof)).is_err());
        command.env.retain(|item| !item.starts_with("SECOND="));
        assert!(policy.check(&command, Some(&proof)).is_err());
        assert!(
            DeferredCommandBindings::default()
                .check(&command, None)
                .is_ok()
        );
    }
}
