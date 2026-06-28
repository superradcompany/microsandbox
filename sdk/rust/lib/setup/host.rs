//! Cross-platform host readiness diagnosis backing `msb doctor`.
//!
//! The SDK owns the *facts*: which runtime files exist and whether the host
//! can run local sandboxes. Rendering (colors, glyphs, hint formatting) lives
//! in the CLI so this layer stays presentation-agnostic.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Outcome of a single host or runtime check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// The check passed.
    Pass,

    /// The check failed in a way that blocks local sandboxes.
    Fail,

    /// The check passed but with a caveat worth surfacing.
    Warn,

    /// Informational only — no pass/fail judgement (e.g. the platform name).
    Info,
}

/// A single labelled check with a human-readable value.
#[derive(Debug, Clone)]
pub struct Check {
    /// Short label, e.g. `"KVM access"`.
    pub label: String,

    /// Outcome of the check.
    pub state: CheckState,

    /// Human-readable value, e.g. `"read/write"` or `"permission denied"`.
    pub value: String,
}

/// A titled group of related checks (e.g. `"Runtime"`, `"Host"`).
#[derive(Debug, Clone)]
pub struct Section {
    /// Section title.
    pub title: String,

    /// Checks within the section, in display order.
    pub checks: Vec<Check>,
}

/// A blocking problem, optionally with an auto-runnable [`Fix`].
#[derive(Debug, Clone)]
pub struct Problem {
    /// One-line headline describing what is wrong.
    pub headline: String,

    /// Ordered hints explaining the cause. Commands live on [`Problem::fix`].
    pub hints: Vec<String>,

    /// A safe, auto-runnable remediation, when one exists. `None` means the
    /// problem can only be fixed by a human (firmware setting, hardware, etc.).
    pub fix: Option<Fix>,
}

/// A safe, auto-runnable remediation for a [`Problem`].
///
/// Every command here is expected to be idempotent and reversible; `msb doctor
/// --fix` runs them after an explicit confirmation.
#[derive(Debug, Clone)]
pub struct Fix {
    /// Human description of what applying this will do.
    pub description: String,

    /// Commands to run, in order.
    pub commands: Vec<FixCommand>,

    /// Whether the persistent part of the fix only takes full effect after the
    /// user starts a fresh login session (e.g. group membership changes).
    pub requires_relogin: bool,
}

/// A single command in a [`Fix`], stored as program + args to avoid any shell
/// quoting or injection concerns when executed.
#[derive(Debug, Clone)]
pub struct FixCommand {
    /// The program to run, e.g. `"sudo"`.
    pub program: String,

    /// Arguments passed to the program.
    pub args: Vec<String>,
}

/// The full result of a host diagnosis.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    /// Rendered sections, in display order.
    pub sections: Vec<Section>,

    /// Problems found, in display order. Empty when the host is ready.
    pub problems: Vec<Problem>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Check {
    pub(crate) fn pass(label: &str, value: &str) -> Self {
        Self {
            label: label.to_string(),
            state: CheckState::Pass,
            value: value.to_string(),
        }
    }

    pub(crate) fn fail(label: &str, value: &str) -> Self {
        Self {
            label: label.to_string(),
            state: CheckState::Fail,
            value: value.to_string(),
        }
    }

    pub(crate) fn info(label: &str, value: &str) -> Self {
        Self {
            label: label.to_string(),
            state: CheckState::Info,
            value: value.to_string(),
        }
    }
}

impl Problem {
    pub(crate) fn new(headline: impl Into<String>, hints: Vec<String>) -> Self {
        Self {
            headline: headline.into(),
            hints,
            fix: None,
        }
    }

    /// Attach an auto-runnable fix.
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}

impl Fix {
    /// Build a fix from a description and an ordered list of commands.
    pub fn new(description: impl Into<String>, commands: Vec<FixCommand>) -> Self {
        Self {
            description: description.into(),
            commands,
            requires_relogin: false,
        }
    }

    /// Mark that the persistent effect needs a fresh login session.
    pub fn requires_relogin(mut self) -> Self {
        self.requires_relogin = true;
        self
    }
}

impl FixCommand {
    /// Build a `sudo`-prefixed command from a borrowed argument list.
    pub fn sudo(args: &[&str]) -> Self {
        Self {
            program: "sudo".to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Render the command as a single copy-pasteable line.
    pub fn display(&self) -> String {
        let mut parts = Vec::with_capacity(self.args.len() + 1);
        parts.push(self.program.as_str());
        parts.extend(self.args.iter().map(String::as_str));
        parts.join(" ")
    }
}

impl Diagnosis {
    /// Whether the host is ready to run local sandboxes.
    pub fn is_healthy(&self) -> bool {
        self.problems.is_empty()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Diagnose runtime installation and host virtualization prerequisites.
///
/// Always returns a populated [`Diagnosis`]; problems are reported as data
/// rather than errors so callers can render the full picture before deciding
/// how to exit.
pub fn diagnose() -> Diagnosis {
    let mut sections = Vec::new();
    let mut problems = Vec::new();

    let (runtime, mut runtime_problems) = runtime_section();
    sections.push(runtime);
    problems.append(&mut runtime_problems);

    let (host, mut host_problems) = host_section();
    sections.push(host);
    problems.append(&mut host_problems);

    Diagnosis { sections, problems }
}

/// Build the "Runtime" section: install root and required runtime files.
fn runtime_section() -> (Section, Vec<Problem>) {
    let base = microsandbox_utils::resolve_home();
    let bin_dir = base.join(microsandbox_utils::BIN_SUBDIR);
    let lib_dir = base.join(microsandbox_utils::LIB_SUBDIR);

    let os = std::env::consts::OS;
    let msb_name = microsandbox_utils::msb_binary_filename(os);
    let libkrunfw_name = microsandbox_utils::libkrunfw_filename(os);

    let msb_ok = bin_dir.join(&msb_name).is_file();
    let libkrunfw_ok = lib_dir.join(&libkrunfw_name).is_file();

    let checks = vec![
        Check::info("Install root", &base.display().to_string()),
        if msb_ok {
            Check::pass("msb", "present")
        } else {
            Check::fail("msb", "missing")
        },
        if libkrunfw_ok {
            Check::pass("libkrunfw", "present")
        } else {
            Check::fail("libkrunfw", "missing")
        },
    ];

    let mut problems = Vec::new();
    if !msb_ok || !libkrunfw_ok {
        problems.push(Problem::new(
            "microsandbox runtime is not fully installed",
            vec![
                format!("expected runtime files under {}", base.display()),
                "install or repair them: msb self update".to_string(),
            ],
        ));
    }

    (
        Section {
            title: "Runtime".to_string(),
            checks,
        },
        problems,
    )
}

/// Build the platform-specific "Host" section.
fn host_section() -> (Section, Vec<Problem>) {
    #[cfg(target_os = "linux")]
    {
        super::linux::host_section()
    }
    #[cfg(target_os = "macos")]
    {
        super::macos::host_section()
    }
    #[cfg(target_os = "windows")]
    {
        super::windows::host_section()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        unsupported_host_section()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn unsupported_host_section() -> (Section, Vec<Problem>) {
    let label = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    (
        Section {
            title: "Host".to_string(),
            checks: vec![Check::fail("Platform", &label)],
        },
        vec![Problem::new(
            "this platform is not supported for local sandboxes",
            vec!["local execution is supported on Linux, macOS (arm64), and Windows".to_string()],
        )],
    )
}
