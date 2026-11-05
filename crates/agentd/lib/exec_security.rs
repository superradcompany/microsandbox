//! Per-child Linux security setup, shared by pipe and PTY execution.

use std::io;

use microsandbox_protocol::exec::{EXEC_CAPABILITY_NAMES, ExecCapabilities, ExecSecurity};

use crate::config::SecurityProfile;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct CapabilityMasks {
    bounding: u64,
    effective: u64,
    permitted: u64,
    inheritable: u64,
    ambient: u64,
}

/// Validated before fork; application performs only child-local syscalls.
#[derive(Clone, Copy, Default)]
pub(crate) struct PreparedSecurity {
    no_new_privileges: bool,
    capabilities: Option<CapabilityMasks>,
    last_cap: u32,
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedSecurity {
    pub(crate) fn new(
        request: Option<&ExecSecurity>,
        profile: SecurityProfile,
    ) -> io::Result<Self> {
        let Some(request) = request else {
            return Ok(Self::default());
        };
        let mut policy = Self {
            no_new_privileges: request.no_new_privileges,
            ..Self::default()
        };
        if let Some(caps) = &request.capabilities {
            let mut masks = CapabilityMasks::parse(caps)?;
            if matches!(profile, SecurityProfile::Restricted) {
                // Per-command settings cannot restore a privilege removed by the sandbox policy.
                let allowed = !(1u64 << 21);
                masks.bounding &= allowed;
                masks.effective &= allowed;
                masks.permitted &= allowed;
                masks.inheritable &= allowed;
                masks.ambient &= allowed;
            }
            let last_cap: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
                .trim()
                .parse()
                .map_err(|_| invalid("invalid kernel cap_last_cap"))?;
            if last_cap >= 64 {
                return Err(invalid(
                    "kernel capability ABI exceeds the supported 64-bit sets",
                ));
            }
            let supported = u64::MAX >> (63 - last_cap);
            if (masks.bounding
                | masks.effective
                | masks.permitted
                | masks.inheritable
                | masks.ambient)
                & !supported
                != 0
            {
                return Err(invalid(
                    "requested capability is unsupported by the guest kernel",
                ));
            }
            policy.capabilities = Some(masks);
            policy.last_cap = last_cap;
        }
        Ok(policy)
    }

    /// Keep setup privileges until UID/GID and resource setup has completed.
    pub(crate) fn before_user(&self) -> io::Result<()> {
        if let Some(caps) = self.capabilities {
            for cap in 0..=self.last_cap {
                let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
                check(present as libc::c_long)?;
                if caps.bounding & (1u64 << cap) != 0 {
                    if present == 0 {
                        return Err(io::Error::from_raw_os_error(libc::EPERM));
                    }
                } else if present != 0 {
                    check(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } as _)?;
                }
            }
            check(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } as _)?;
        }
        Ok(())
    }

    /// Final operation before exec, after user and rlimit setup.
    pub(crate) fn after_user(&self) -> io::Result<()> {
        if let Some(caps) = self.capabilities {
            check(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } as _)?;
            check(unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                )
            } as _)?;
            let header = CapHeader {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [CapData::default(); 2];
            for (index, word) in data.iter_mut().enumerate() {
                word.effective = (caps.effective >> (32 * index)) as u32;
                word.permitted = (caps.permitted >> (32 * index)) as u32;
                word.inheritable = (caps.inheritable >> (32 * index)) as u32;
            }
            check(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) })?;
            for cap in 0..=self.last_cap {
                if caps.ambient & (1u64 << cap) != 0 {
                    check(unsafe {
                        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, cap, 0, 0)
                    } as _)?;
                }
            }
        }
        if self.no_new_privileges {
            check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } as _)?;
        }
        Ok(())
    }
}

impl CapabilityMasks {
    fn parse(caps: &ExecCapabilities) -> io::Result<Self> {
        let result = Self {
            bounding: capability_mask(&caps.bounding)?,
            effective: capability_mask(&caps.effective)?,
            permitted: capability_mask(&caps.permitted)?,
            inheritable: capability_mask(&caps.inheritable)?,
            ambient: capability_mask(&caps.ambient)?,
        };
        if result.effective & !result.permitted != 0 {
            return Err(invalid(
                "effective capabilities must be a subset of permitted",
            ));
        }
        if result.ambient & !(result.permitted & result.inheritable) != 0 {
            return Err(invalid(
                "ambient capabilities must be permitted and inheritable",
            ));
        }
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn capability_mask(names: &[String]) -> io::Result<u64> {
    names.iter().try_fold(0, |mask, name| {
        let bit = EXEC_CAPABILITY_NAMES
            .iter()
            .position(|known| *known == name)
            .ok_or_else(|| invalid(format!("unknown Linux capability: {name}")))?;
        Ok(mask | (1u64 << bit))
    })
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn check(result: libc::c_long) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
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
    fn rejects_unknown_and_inconsistent_capabilities() {
        let mut caps = ExecCapabilities {
            effective: vec!["CAP_TYPO".into()],
            ..Default::default()
        };
        assert!(CapabilityMasks::parse(&caps).is_err());
        caps.effective = vec!["CAP_CHOWN".into()];
        assert!(CapabilityMasks::parse(&caps).is_err());
        caps.permitted = caps.effective.clone();
        caps.ambient = caps.effective.clone();
        assert!(CapabilityMasks::parse(&caps).is_err());
        caps.inheritable = caps.effective.clone();
        assert!(CapabilityMasks::parse(&caps).is_ok());
        assert_eq!(
            capability_mask(&["CAP_CHECKPOINT_RESTORE".into()]).unwrap(),
            1u64 << 40
        );
    }

    #[test]
    fn per_command_capabilities_cannot_override_restricted_profile() {
        let policy = PreparedSecurity::new(
            Some(&ExecSecurity {
                no_new_privileges: false,
                capabilities: Some(ExecCapabilities {
                    bounding: vec!["CAP_SYS_ADMIN".into()],
                    effective: vec!["CAP_SYS_ADMIN".into()],
                    permitted: vec!["CAP_SYS_ADMIN".into()],
                    inheritable: vec!["CAP_SYS_ADMIN".into()],
                    ambient: vec!["CAP_SYS_ADMIN".into()],
                }),
            }),
            SecurityProfile::Restricted,
        )
        .unwrap();
        let caps = policy.capabilities.unwrap();
        assert_eq!(
            caps.bounding | caps.effective | caps.permitted | caps.inheritable | caps.ambient,
            0
        );
    }
}
