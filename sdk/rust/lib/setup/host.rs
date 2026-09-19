//! Cross-platform host readiness diagnosis backing `msb doctor`.
//!
//! The SDK owns the *facts*: which runtime files exist and whether the host
//! can run local sandboxes. Rendering (colors, glyphs, hint formatting) lives
//! in the CLI so this layer stays presentation-agnostic.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use microsandbox_utils::copy::{FastCopyStrategy, fast_copy_with_strategy};

use crate::MicrosandboxResult;
use crate::config::{GlobalConfig, layers::BackendConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    pub(crate) fn warn(label: &str, value: &str) -> Self {
        Self {
            label: label.to_string(),
            state: CheckState::Warn,
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

    let (runtime, mut runtime_problems) = runtime_section(BackendConfig::load());
    sections.push(runtime);
    problems.append(&mut runtime_problems);

    let (host, mut host_problems) = host_section();
    sections.push(host);
    problems.append(&mut host_problems);

    Diagnosis { sections, problems }
}

/// Build the "Runtime" section: install root and resolved runtime files.
fn runtime_section(config: MicrosandboxResult<BackendConfig>) -> (Section, Vec<Problem>) {
    let sources = match config
        .and_then(|config| config.prepare_for_local_backend(Default::default()))
    {
        Ok(config) => config,
        Err(error) => {
            let unavailable = "unavailable because configuration could not be resolved".to_string();
            return runtime_section_from_results(
                None,
                Some(error.to_string()),
                Err(unavailable.clone()),
                Err(unavailable),
            );
        }
    };
    let config = sources.resolved_config();
    let base = config.home();
    let msb = resolve_msb_runtime_file(config);
    let libkrunfw = resolve_libkrunfw_runtime_file(config);

    let (mut section, problems) = runtime_section_from_results(Some(&base), None, msb, libkrunfw);

    // `clone=auto` is only cheap when both artifacts live on a filesystem whose native clone
    // primitive succeeds. Probe the configured home itself so bind mounts and per-directory
    // volume boundaries are represented instead of guessing from the host's filesystem type.
    if base.is_dir() {
        section.checks.push(root_clone_check(&base));
    }

    (section, problems)
}

fn runtime_section_from_results(
    base: Option<&Path>,
    config_error: Option<String>,
    msb: Result<PathBuf, String>,
    libkrunfw: Result<PathBuf, String>,
) -> (Section, Vec<Problem>) {
    let home = match base {
        Some(base) => Check::info("MSB_HOME", &base.display().to_string()),
        None => Check::fail("MSB_HOME", "unavailable"),
    };
    let mut checks = vec![Check::info("Version", &format!("v{PACKAGE_VERSION}")), home];
    if config_error.is_some() {
        checks.push(Check::fail("config", "invalid"));
    }
    checks.extend([
        runtime_file_check("msb", &msb),
        runtime_file_check("libkrunfw", &libkrunfw),
    ]);

    let mut problems = Vec::new();
    if let Some(error) = config_error {
        problems.push(Problem::new(
            "microsandbox config could not be read",
            vec![
                error,
                "fix the reported config file; managed.json must be corrected by its administrator"
                    .to_string(),
            ],
        ));
    } else if msb.is_err() || libkrunfw.is_err() {
        let mut hints = Vec::new();
        if let Err(error) = &msb {
            hints.push(format!("msb: {error}"));
        }
        if let Err(error) = &libkrunfw {
            hints.push(format!("libkrunfw: {error}"));
        }
        hints.push("libkrunfw may live beside the resolved msb binary or under ../lib".to_string());
        hints.push("standalone install: repair with msb self update".to_string());
        hints.push(
            "package-manager install: reinstall or repair the microsandbox package".to_string(),
        );

        problems.push(Problem::new(
            "microsandbox runtime could not be resolved",
            hints,
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

fn runtime_file_check(label: &str, result: &Result<PathBuf, String>) -> Check {
    match result {
        Ok(path) => Check::pass(label, &path.display().to_string()),
        Err(_) => Check::fail(label, "not found"),
    }
}

/// Resolve the strategy that `clone=auto` can use inside `MSB_HOME`.
fn root_clone_check(base: &Path) -> Check {
    match probe_root_clone(base) {
        Ok(FastCopyStrategy::Reflink) => Check::pass("Root clone", "reflink supported"),
        Ok(FastCopyStrategy::SparseCopy) => {
            Check::warn("Root clone", "copy fallback — reflink unavailable")
        }
        Err(error) => Check::warn(
            "Root clone",
            &format!("not checked — {}", concise_io_error(&error)),
        ),
    }
}

/// Exercise the same portable clone implementation used by flat sandbox roots.
fn probe_root_clone(base: &Path) -> io::Result<FastCopyStrategy> {
    const PROBE_LEN: usize = 64 * 1024;

    let probe = tempfile::Builder::new()
        .prefix(".msb-doctor-clone-")
        .tempdir_in(base)?;
    let source = probe.path().join("source");
    let destination = probe.path().join("destination");

    // ReFS block clones require cluster-aligned ranges. A 64-KiB data-bearing file is accepted by
    // both of its common cluster sizes and also prevents a sparse-hole shortcut from masquerading
    // as a successful clone on other platforms.
    let mut source_file = File::create(&source)?;
    source_file.write_all(&vec![0xa5; PROBE_LEN])?;
    source_file.sync_all()?;
    drop(source_file);

    let (_, strategy) = fast_copy_with_strategy(&source, &destination)?;
    probe.close()?;
    Ok(strategy)
}

fn concise_io_error(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "MSB_HOME is unavailable",
        io::ErrorKind::PermissionDenied => "permission denied",
        io::ErrorKind::StorageFull => "storage is full",
        _ => "probe failed",
    }
}

fn resolve_msb_runtime_file(config: &GlobalConfig) -> Result<PathBuf, String> {
    let path = super::resolve_runtime(config)
        .map_err(|error| error.to_string())?
        .msb_path;
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("resolved path is not a file: {}", path.display()))
    }
}

fn resolve_libkrunfw_runtime_file(config: &GlobalConfig) -> Result<PathBuf, String> {
    super::resolve_runtime(config)
        .map(|runtime| runtime.libkrunfw_path)
        .map_err(|error| error.to_string())
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_section_uses_managed_paths_and_reports_config_errors() {
        let _env_guard = crate::test_support::lock_env();
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.json");
        let managed = dir.path().join("managed.json");
        let msb = dir.path().join("msb");
        let libkrunfw = dir.path().join("libkrunfw");
        std::fs::write(&msb, "").unwrap();
        std::fs::write(&libkrunfw, "").unwrap();
        let previous =
            ["MSB_PATH", "MSB_LIBKRUNFW_PATH"].map(|name| (name, std::env::var_os(name)));
        let _restore = scopeguard::guard(previous, |previous| {
            for (name, value) in previous {
                // SAFETY: the shared environment lock remains held during restoration.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        });
        let user_config = serde_json::json!({
            "home": dir.path(),
            "paths": {"msb": "/user/msb", "libkrunfw": "/user/libkrunfw"}
        });
        std::fs::write(&user, user_config.to_string()).unwrap();
        for with_managed in [false, true] {
            let (env_msb, env_libkrunfw) = if with_managed {
                (Path::new("/env/msb"), Path::new("/env/libkrunfw"))
            } else {
                (msb.as_path(), libkrunfw.as_path())
            };
            // SAFETY: environment-dependent SDK tests hold the shared lock.
            unsafe {
                std::env::set_var("MSB_PATH", env_msb);
                std::env::set_var("MSB_LIBKRUNFW_PATH", env_libkrunfw);
            }
            if with_managed {
                let policy = serde_json::json!({"overrides": {
                    "paths": {"msb": msb, "libkrunfw": libkrunfw}
                }});
                std::fs::write(&managed, policy.to_string()).unwrap();
            }
            let (section, problems) =
                runtime_section(BackendConfig::load_from(&user, Some(&managed)));
            for (label, expected) in [("msb", &msb), ("libkrunfw", &libkrunfw)] {
                let check = section
                    .checks
                    .iter()
                    .find(|check| check.label == label)
                    .unwrap();
                assert_eq!(check.state, CheckState::Pass);
                assert_eq!(check.value, expected.display().to_string());
            }
            assert!(problems.is_empty());
        }
        for invalid in [&managed, &user] {
            std::fs::write(&user, user_config.to_string()).unwrap();
            std::fs::write(&managed, "{}").unwrap();
            std::fs::write(invalid, "invalid").unwrap();
            let (section, problems) =
                runtime_section(BackendConfig::load_from(&user, Some(&managed)));
            assert!(!problems.is_empty());
            assert!(
                section
                    .checks
                    .iter()
                    .any(|check| check.label == "config" && check.state == CheckState::Fail)
            );
            assert!(
                section
                    .checks
                    .iter()
                    .filter(|check| ["msb", "libkrunfw"].contains(&check.label.as_str()))
                    .all(|check| check.state == CheckState::Fail)
            );
        }
    }

    #[test]
    fn root_clone_probe_cleans_up_its_temporary_files() {
        let base = tempfile::tempdir().unwrap();

        let strategy = probe_root_clone(base.path()).unwrap();

        assert!(matches!(
            strategy,
            FastCopyStrategy::Reflink | FastCopyStrategy::SparseCopy
        ));
        assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
    }

    #[test]
    fn runtime_section_accepts_resolved_side_by_side_runtime() {
        let dir = PathBuf::from("C:/Tools/microsandbox");
        let msb = dir.join(microsandbox_utils::msb_binary_filename("windows"));
        let libkrunfw = dir.join(microsandbox_utils::libkrunfw_filename("windows"));

        let (section, problems) = runtime_section_from_results(
            Some(Path::new("C:/Users/me/.microsandbox")),
            None,
            Ok(msb.clone()),
            Ok(libkrunfw.clone()),
        );

        assert!(problems.is_empty());
        assert_eq!(section.checks[0].label, "Version");
        assert_eq!(section.checks[0].value, format!("v{PACKAGE_VERSION}"));
        assert_eq!(section.checks[1].label, "MSB_HOME");
        assert_eq!(section.checks[2].state, CheckState::Pass);
        assert_eq!(section.checks[2].value, msb.display().to_string());
        assert_eq!(section.checks[3].state, CheckState::Pass);
        assert_eq!(section.checks[3].value, libkrunfw.display().to_string());
    }

    #[test]
    fn runtime_section_reports_resolution_errors() {
        let (section, problems) = runtime_section_from_results(
            Some(Path::new("/home/me/.microsandbox")),
            None,
            Err("resolved path is not a file: /tmp/msb".to_string()),
            Err("searched: /tmp/libkrunfw.so.5.6.1".to_string()),
        );

        assert_eq!(section.checks[2].state, CheckState::Fail);
        assert_eq!(section.checks[3].state, CheckState::Fail);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].hints[0].contains("/tmp/msb"));
        assert!(problems[0].hints[1].contains("/tmp/libkrunfw.so.5.6.1"));
    }

    #[test]
    fn runtime_section_reports_config_errors() {
        let (section, problems) = runtime_section_from_results(
            Some(Path::new("/home/me/.microsandbox")),
            Some("failed to parse config `/home/me/.microsandbox/config.json`".to_string()),
            Ok(PathBuf::from("/usr/bin/msb")),
            Ok(PathBuf::from("/usr/lib/libkrunfw.so.5.6.1")),
        );

        assert_eq!(section.checks[2].label, "config");
        assert_eq!(section.checks[2].state, CheckState::Fail);
        assert_eq!(problems.len(), 1);
        assert_eq!(
            problems[0].headline,
            "microsandbox config could not be read"
        );
    }
}
