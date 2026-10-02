//! Project global defaults into the v0.7.0 runtime secret contract.

use crate::SecretsConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve saved defaults into fields understood by released v0.7 runtimes.
/// This projection is launch-only: the source retains defaults for later edits.
pub fn to_previous_version(source: &SecretsConfig) -> SecretsConfig {
    let mut policy = source.clone();
    policy.passthrough_hosts = None;
    for entry in &mut policy.secrets {
        if entry.violation_action.is_none()
            && let Some(hosts) = &source.passthrough_hosts
        {
            for host in hosts {
                if !entry.passthrough_hosts.contains(host) {
                    entry.passthrough_hosts.push(host.clone());
                }
            }
        }
    }
    policy
}
