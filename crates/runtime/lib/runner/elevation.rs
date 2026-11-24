//! By default an elevated runtime keeps the UAC boundary: its pipes get their default
//! security. When the launcher passes `share_elevated_sandboxes` and this runtime is the full
//! half of a split token, the pipes are shared as [`microsandbox_utils::elevation_share`]
//! describes.

use std::ffi::OsStr;
use std::io;
use std::sync::RwLock;

use microsandbox_utils::elevation_share::{self, SharedSecurity};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Security::TOKEN_ELEVATION_TYPE;

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The security this runtime's pipes share with, built once when the runtime starts, before
/// any pipe exists; `None` keeps the default security.
static PIPE_SECURITY: RwLock<Option<SharedSecurity>> = RwLock::new(None);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide from the launch's opt-in whether this runtime shares its pipes with non-elevated
/// runs in its sign-in session. Without the opt-in nothing is queried. With it, failing to
/// read this process's elevation type, or to build the shared security in an elevated one,
/// fails startup rather than silently keeping the default security.
pub(crate) fn share_with_non_elevated(opt_in: bool) -> RuntimeResult<()> {
    share_with_non_elevated_as(
        opt_in,
        elevation_share::elevation_type,
        elevation_share::shared_pipe_security,
    )
}

/// Create a named pipe server instance, shared with non-elevated runs of this account when
/// [`share_with_non_elevated`] decided so.
pub(crate) fn create_shared_pipe(
    options: &ServerOptions,
    name: impl AsRef<OsStr>,
) -> io::Result<NamedPipeServer> {
    let security = PIPE_SECURITY
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(security) = security.as_ref() else {
        return options.create(name);
    };

    let mut attributes = security.attributes();
    // SAFETY: the attributes, and the descriptor they point at, live until the call returns.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}

/// [`share_with_non_elevated`] with this process's token elevation type read by `elevation`
/// and the shared pipe security built by `security`.
fn share_with_non_elevated_as(
    opt_in: bool,
    elevation: impl FnOnce() -> io::Result<TOKEN_ELEVATION_TYPE>,
    security: impl FnOnce() -> io::Result<SharedSecurity>,
) -> RuntimeResult<()> {
    set_pipe_security(None);

    if !opt_in {
        return Ok(());
    }

    let elevation = elevation().map_err(|error| {
        RuntimeError::Custom(format!(
            "could not read this process's token elevation type while \
             runtime.share_elevated_sandboxes is on: {error}"
        ))
    })?;

    if !elevation_share::shares_with_non_elevated(opt_in, elevation) {
        return Ok(());
    }

    let security = security().map_err(|error| {
        RuntimeError::Custom(format!(
            "could not build the shared pipe security while runtime.share_elevated_sandboxes \
             is on: {error}"
        ))
    })?;

    set_pipe_security(Some(security));

    Ok(())
}

fn set_pipe_security(security: Option<SharedSecurity>) {
    *PIPE_SECURITY
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = security;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process;
    use std::ptr::null_mut;
    use std::slice::from_raw_parts;
    use std::sync::{Mutex, MutexGuard};

    use microsandbox_utils::elevation_share::{self, SharedSecurity};
    use tokio::net::windows::named_pipe::ServerOptions;
    use tokio::runtime::Builder;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, TokenElevationTypeDefault, TokenElevationTypeFull,
        TokenElevationTypeLimited,
    };

    use super::{PIPE_SECURITY, create_shared_pipe, set_pipe_security, share_with_non_elevated_as};

    /// Serializes the tests that set this process's sharing decision.
    static DECISION: Mutex<()> = Mutex::new(());

    /// Holds [`DECISION`] and resets the decision when dropped, also when a test panics, so
    /// no test leaks sharing into another.
    struct Decision {
        _lock: MutexGuard<'static, ()>,
    }

    impl Decision {
        fn take() -> Self {
            Self {
                _lock: DECISION
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            }
        }
    }

    impl Drop for Decision {
        fn drop(&mut self) {
            set_pipe_security(None);
        }
    }

    /// Whether this process's pipes are shared now.
    fn shared() -> bool {
        PIPE_SECURITY.read().unwrap().is_some()
    }

    /// A shared pipe security builder that a test expects not to be called.
    fn unbuilt() -> io::Result<SharedSecurity> {
        unreachable!("the shared pipe security was built")
    }

    /// The DACL of the kernel object `handle`, in lowercase SDDL.
    fn dacl(handle: HANDLE) -> String {
        let mut descriptor = null_mut();
        let error = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(error, 0, "read the DACL");

        let mut text = null_mut();
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        assert_ne!(converted, 0, "{}", io::Error::last_os_error());

        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let sddl = String::from_utf16_lossy(unsafe { from_raw_parts(text, len) });
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }

        sddl.to_ascii_lowercase()
    }

    /// The opt-in reaches the runtime's pipes only in the full half of a split token: then a
    /// pipe created the way the runtime's servers create theirs grants this sign-in's logon
    /// SID client rights (`0x12019b`); every other start keeps the default security, which
    /// does not. Without the opt-in the elevation type is not even read. Run elevated
    /// (administrator): only an elevated process may own a pipe by Administrators.
    #[test]
    fn opt_in_shares_the_runtime_pipes_only_when_elevated() {
        assert!(
            elevation_share::is_elevated().unwrap(),
            "this test creates pipes owned by Administrators: run it elevated (administrator)"
        );

        let _decision = Decision::take();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let _guard = runtime.enter();

        let client_ace = format!(
            "(a;;0x12019b;;;{})",
            elevation_share::current_logon_sid()
                .unwrap()
                .to_ascii_lowercase()
        );
        for (index, (opt_in, elevation, shared)) in [
            (true, TokenElevationTypeFull, true),
            (false, TokenElevationTypeFull, false),
            (true, TokenElevationTypeDefault, false),
            (true, TokenElevationTypeLimited, false),
        ]
        .into_iter()
        .enumerate()
        {
            let mut queried = false;
            share_with_non_elevated_as(
                opt_in,
                || {
                    queried = true;
                    Ok(elevation)
                },
                elevation_share::shared_pipe_security,
            )
            .unwrap();

            assert_eq!(queried, opt_in, "opt_in={opt_in}: elevation type read");

            let name = format!(
                r"\\.\pipe\msb-runtime-elevation-test-{}-{index}",
                process::id()
            );
            let mut options = ServerOptions::new();
            options.first_pipe_instance(true);
            let pipe = create_shared_pipe(&options, &name).unwrap();
            let dacl_sddl = dacl(pipe.as_raw_handle());
            println!("opt_in={opt_in} elevation type {elevation}: pipe {dacl_sddl}");

            assert_eq!(
                dacl_sddl.contains(&client_ace),
                shared,
                "pipe DACL for opt_in={opt_in} elevation type {elevation}: {dacl_sddl}"
            );
            // Only the sign-in is granted client rights, never the account.
            assert_eq!(
                dacl_sddl.matches("(a;;0x12019b;;;").count(),
                usize::from(shared),
                "pipe DACL for opt_in={opt_in} elevation type {elevation}: {dacl_sddl}"
            );
        }

        share_with_non_elevated_as(false, || unreachable!(), unbuilt).unwrap();

        assert!(!shared());
    }

    /// With the opt-in, a runtime that cannot read its elevation type, or cannot build the
    /// shared security in an elevated token, fails to start instead of keeping the default
    /// security, and says which; without the opt-in, or in a token that does not share,
    /// neither matters.
    #[test]
    fn opt_in_fails_startup_when_sharing_cannot_be_set_up() {
        let _decision = Decision::take();
        let failure = || io::Error::other("injected");

        let unread = share_with_non_elevated_as(true, || Err(failure()), unbuilt).unwrap_err();
        let unbuildable =
            share_with_non_elevated_as(true, || Ok(TokenElevationTypeFull), || Err(failure()))
                .unwrap_err();

        assert_eq!(
            unread.to_string(),
            "could not read this process's token elevation type while \
             runtime.share_elevated_sandboxes is on: injected"
        );
        assert_eq!(
            unbuildable.to_string(),
            "could not build the shared pipe security while runtime.share_elevated_sandboxes \
             is on: injected"
        );
        assert!(!shared());

        share_with_non_elevated_as(false, || Err(failure()), unbuilt).unwrap();
        share_with_non_elevated_as(true, || Ok(TokenElevationTypeDefault), unbuilt).unwrap();

        assert!(!shared());
    }
}
