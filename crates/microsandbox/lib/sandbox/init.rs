//! Guest init-handoff types for the sandbox boot path.
//!
//! When [`HandoffInit`] is set on a [`super::SandboxConfig`], agentd
//! finishes its setup, forks, and the parent execve's into the
//! configured init binary — typically `systemd`, but any init works.
//! agentd continues as a normal process, serving host requests over
//! virtio-serial.
//!
//! Users construct this via the builder methods on
//! [`super::SandboxBuilder`]:
//!
//! ```ignore
//! Sandbox::builder("dev")
//!     .image("debian:bookworm")
//!     .init("/lib/systemd/systemd", ["--unit=multi-user.target"])
//!     .build().await?;
//!
//! Sandbox::builder("dev")
//!     .image("debian:bookworm")
//!     .init_with("/lib/systemd/systemd", |i| {
//!         i.args(["--unit=multi-user.target"])
//!          .env("container", "microsandbox")
//!     })
//!     .build().await?;
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fully-assembled handoff-init specification stored on a sandbox
/// config and serialised into the `MSB_HANDOFF_INIT*` env vars at
/// spawn time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffInit {
    /// Absolute path inside the guest rootfs.
    pub program: PathBuf,

    /// Supplemental argv. `argv[0]` is implicitly `program`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Extra env vars merged on top of the inherited env.
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

/// Builder for the `args` + `env` portion of [`HandoffInit`].
///
/// The program path is supplied positionally to
/// [`super::SandboxBuilder::init_with`], not stored in this builder —
/// matching how [`super::ExecOptionsBuilder`] omits the command name.
#[derive(Default)]
pub struct InitOptionsBuilder {
    args: Vec<String>,
    env: Vec<(String, String)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HandoffInit {
    /// Construct a [`HandoffInit`] from a program path and (optional)
    /// argv list.
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
        }
    }
}

impl InitOptionsBuilder {
    /// Append a single argv entry.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append multiple argv entries.
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an env var for the init process. Repeatable; later entries
    /// with the same key shadow earlier ones inside the guest.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Set multiple env vars at once.
    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Finalise into `(args, env)`. Called by the SandboxBuilder shim.
    pub(crate) fn build(self) -> (Vec<String>, Vec<(String, String)>) {
        (self.args, self.env)
    }
}
