//! Linux host prerequisite checks for local sandbox execution.
//!
//! Local sandboxes need KVM through `/dev/kvm`. These checks diagnose the
//! common failure modes — missing CPU virtualization, an absent device node,
//! and a device the current user cannot open — and surface copy-pasteable
//! remediation commands. Nothing here mutates the host.

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::host::{Check, Fix, FixCommand, Problem, Section};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KVM_DEVICE: &str = "/dev/kvm";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Diagnose Linux host virtualization prerequisites.
pub(super) fn host_section() -> (Section, Vec<Problem>) {
    let mut checks = Vec::new();
    let mut problems = Vec::new();

    let arch = std::env::consts::ARCH;
    checks.push(Check::info("Platform", &format!("Linux {arch}")));

    // x86 requires a VT-x / AMD-V flag in /proc/cpuinfo. On aarch64 the flag
    // isn't reported there — KVM availability is reflected by /dev/kvm itself —
    // so the cpuinfo probe would misfire; skip it and rely on the device check.
    if arch == "x86_64" {
        match cpu_virt_flag() {
            Some(flag) => checks.push(Check::pass("CPU virt", flag)),
            None => {
                checks.push(Check::fail("CPU virt", "not found"));
                problems.push(Problem::new(
                    "CPU virtualization is not available",
                    vec![
                        "no vmx (Intel) or svm (AMD) flag in /proc/cpuinfo".to_string(),
                        "enable virtualization (VT-x / AMD-V) in your BIOS or UEFI firmware"
                            .to_string(),
                        "inside a VM, enable nested virtualization on the host".to_string(),
                    ],
                ));
            }
        }
    }

    let kvm = Path::new(KVM_DEVICE);
    if !kvm.exists() {
        checks.push(Check::fail("KVM device", "missing"));
        let mut problem = Problem::new(
            format!("{KVM_DEVICE} is not present"),
            vec![
                "the KVM kernel module is not loaded".to_string(),
                "in containers or CI, the host must expose /dev/kvm to this environment"
                    .to_string(),
            ],
        );
        // Only the x86 vendor modules are safe to load by name. On aarch64 KVM
        // is typically built in, so there's nothing to modprobe — leave it
        // advisory rather than guess.
        if let Some(module) = kvm_module() {
            problem = problem.with_fix(Fix::new(
                format!("load the {module} kernel module"),
                vec![FixCommand::sudo(&["modprobe", module])],
            ));
        }
        problems.push(problem);
        return (section(checks), problems);
    }
    checks.push(Check::pass("KVM device", KVM_DEVICE));

    // Opening O_RDWR is the same access libkrun needs and is a side-effect-free
    // permission probe — we drop the handle immediately.
    match OpenOptions::new().read(true).write(true).open(kvm) {
        Ok(_) => checks.push(Check::pass("KVM access", "read/write")),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            checks.push(Check::fail("KVM access", "permission denied"));
            problems.push(kvm_permission_problem());
        }
        Err(err) => {
            checks.push(Check::fail("KVM access", "unavailable"));
            problems.push(Problem::new(
                format!("{KVM_DEVICE} could not be opened"),
                vec![format!("opening {KVM_DEVICE} failed: {err}")],
            ));
        }
    }

    (section(checks), problems)
}

fn section(checks: Vec<Check>) -> Section {
    Section {
        title: "Host".to_string(),
        checks,
    }
}

/// Return the first virtualization flag found in `/proc/cpuinfo`, if any.
fn cpu_virt_flag() -> Option<&'static str> {
    let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in info.lines() {
        if line.starts_with("flags") {
            let flags = line.split(':').nth(1).unwrap_or("");
            if flags.split_whitespace().any(|f| f == "vmx") {
                return Some("vmx");
            }
            if flags.split_whitespace().any(|f| f == "svm") {
                return Some("svm");
            }
        }
    }
    None
}

/// Build the `/dev/kvm` permission failure, with a fix tailored to whether the
/// user already belongs to the device's owning group.
///
/// The fix pairs two safe, reversible commands: `setfacl` grants the running
/// user access immediately (this boot), while `usermod -aG` makes it persist
/// across reboots. We can only build them once we know the real username, so a
/// missing username degrades to advisory hints.
fn kvm_permission_problem() -> Problem {
    let group = device_group(KVM_DEVICE);
    let group_label = group.clone().unwrap_or_else(|| "kvm".to_string());
    let already_member = group.as_deref().map(user_in_group).unwrap_or(false);
    let user = current_username();

    let cause = if already_member {
        format!("you are in the '{group_label}' group, but this login session predates the change")
    } else {
        match &group {
            Some(g) => format!("{KVM_DEVICE} is owned by group '{g}', which your user is not in"),
            None => format!("your user lacks read/write access to {KVM_DEVICE}"),
        }
    };

    let mut problem = Problem::new(
        format!("{KVM_DEVICE} is not accessible by your user"),
        vec![cause],
    );

    let Some(user) = user else {
        return problem;
    };
    let acl = format!("u:{user}:rw");

    if already_member {
        // Membership is set; just grant this session direct access.
        problem = problem.with_fix(Fix::new(
            format!("grant {user} access to {KVM_DEVICE} for the current session"),
            vec![FixCommand::sudo(&[
                "setfacl",
                "-m",
                acl.as_str(),
                KVM_DEVICE,
            ])],
        ));
    } else {
        problem = problem.with_fix(
            Fix::new(
                format!("add {user} to the '{group_label}' group and grant access now"),
                vec![
                    FixCommand::sudo(&["usermod", "-aG", group_label.as_str(), user.as_str()]),
                    FixCommand::sudo(&["setfacl", "-m", acl.as_str(), KVM_DEVICE]),
                ],
            )
            .requires_relogin(),
        );
    }

    problem
}

/// The x86 vendor KVM module to load, derived from the CPU virtualization flag.
fn kvm_module() -> Option<&'static str> {
    match cpu_virt_flag() {
        Some("vmx") => Some("kvm_intel"),
        Some("svm") => Some("kvm_amd"),
        _ => None,
    }
}

/// Resolve the current effective user's login name.
fn current_username() -> Option<String> {
    if let Ok(user) = std::env::var("USER")
        && !user.is_empty()
    {
        return Some(user);
    }

    // SAFETY: getpwuid returns a pointer into a shared static buffer; the doctor
    // command is single-threaded, and we copy the name out immediately.
    unsafe {
        let entry = libc::getpwuid(libc::geteuid());
        if entry.is_null() {
            return None;
        }
        Some(
            CStr::from_ptr((*entry).pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Resolve the owning group name of a device path.
fn device_group(path: &str) -> Option<String> {
    let gid = std::fs::metadata(path).ok()?.gid();
    group_name(gid)
}

/// Resolve a gid to its group name.
fn group_name(gid: libc::gid_t) -> Option<String> {
    // SAFETY: getgrgid returns a pointer into a shared static buffer. The doctor
    // command is single-threaded, and we copy the name out immediately before
    // any further libc call can overwrite the buffer.
    unsafe {
        let entry = libc::getgrgid(gid);
        if entry.is_null() {
            return None;
        }
        Some(
            CStr::from_ptr((*entry).gr_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Whether the current process belongs to the named group.
fn user_in_group(name: &str) -> bool {
    // SAFETY: the first call queries the count; the second fills the buffer.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }

    let mut gids = vec![0 as libc::gid_t; count as usize];
    let filled = unsafe { libc::getgroups(count, gids.as_mut_ptr()) };
    if filled < 0 {
        return false;
    }
    gids.truncate(filled as usize);

    gids.into_iter().filter_map(group_name).any(|g| g == name)
}
