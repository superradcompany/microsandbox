//! Resource limit helpers shared between PID 1 init (sandbox-wide baseline)
//! and exec sessions (per-request limits).

use microsandbox_protocol::exec::{ExecRlimit, RlimitResource};

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Maps a wire-format resource name to the Linux `RLIMIT_*` constant, or
/// `None` if the name is not a known [`RlimitResource`].
pub(crate) fn parse_rlimit_resource(name: &str) -> Option<libc::c_int> {
    RlimitResource::try_from(name).ok().map(resource_to_libc_id)
}

/// Pre-parses rlimits into `(resource_id, rlimit)` tuples ready for
/// `setrlimit()`. Unknown resource names are filtered out.
pub(crate) fn to_libc(rlimits: &[ExecRlimit]) -> Vec<(libc::c_int, libc::rlimit)> {
    rlimits
        .iter()
        .filter_map(|rl| {
            Some((
                parse_rlimit_resource(&rl.resource)?,
                libc::rlimit {
                    rlim_cur: rl.soft,
                    rlim_max: rl.hard,
                },
            ))
        })
        .collect()
}

/// Applies sandbox-wide resource limits to the current process (PID 1).
///
/// Applied before other init work so every later guest process inherits the
/// raised baseline automatically, including bootstrap daemons that are not
/// started through the per-exec API.
///
/// Callers must have validated resource names upfront (e.g. via
/// [`AgentdConfig::from_env`](crate::config::AgentdConfig::from_env)); unknown
/// names here produce an [`AgentdError::Init`] rather than silently skipping.
pub(crate) fn apply_baseline(rlimits: &[ExecRlimit]) -> AgentdResult<()> {
    for rlimit in rlimits {
        let resource = parse_rlimit_resource(&rlimit.resource).ok_or_else(|| {
            AgentdError::Init(format!("unknown rlimit resource: {}", rlimit.resource))
        })?;
        let limit = libc::rlimit {
            rlim_cur: rlimit.soft,
            rlim_max: rlimit.hard,
        };
        if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
            return Err(AgentdError::Init(format!(
                "failed to apply rlimit {}={}:{}: {}",
                rlimit.resource,
                rlimit.soft,
                rlimit.hard,
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Maps a [`RlimitResource`] to its Linux `RLIMIT_*` integer id.
fn resource_to_libc_id(resource: RlimitResource) -> libc::c_int {
    // Linux x86_64 RLIMIT_* values for resources not exposed by libc on all platforms.
    const RLIMIT_LOCKS: libc::c_int = 10;
    const RLIMIT_SIGPENDING: libc::c_int = 11;
    const RLIMIT_MSGQUEUE: libc::c_int = 12;
    const RLIMIT_NICE: libc::c_int = 13;
    const RLIMIT_RTPRIO: libc::c_int = 14;
    const RLIMIT_RTTIME: libc::c_int = 15;

    match resource {
        RlimitResource::Cpu => libc::RLIMIT_CPU as _,
        RlimitResource::Fsize => libc::RLIMIT_FSIZE as _,
        RlimitResource::Data => libc::RLIMIT_DATA as _,
        RlimitResource::Stack => libc::RLIMIT_STACK as _,
        RlimitResource::Core => libc::RLIMIT_CORE as _,
        RlimitResource::Rss => libc::RLIMIT_RSS as _,
        RlimitResource::Nproc => libc::RLIMIT_NPROC as _,
        RlimitResource::Nofile => libc::RLIMIT_NOFILE as _,
        RlimitResource::Memlock => libc::RLIMIT_MEMLOCK as _,
        RlimitResource::As => libc::RLIMIT_AS as _,
        RlimitResource::Locks => RLIMIT_LOCKS,
        RlimitResource::Sigpending => RLIMIT_SIGPENDING,
        RlimitResource::Msgqueue => RLIMIT_MSGQUEUE,
        RlimitResource::Nice => RLIMIT_NICE,
        RlimitResource::Rtprio => RLIMIT_RTPRIO,
        RlimitResource::Rttime => RLIMIT_RTTIME,
    }
}
