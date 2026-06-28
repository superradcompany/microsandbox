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
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DeviceGroup {
    name: Option<String>,
    gid: libc::gid_t,
    grants_read_write: bool,
}

#[derive(Debug, Clone)]
struct UserInfo {
    name: String,
    primary_gid: libc::gid_t,
}

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
/// The fix always prefers the narrowest safe mutation: `setfacl` grants the
/// running user access for this boot, and `usermod -aG` is offered only when the
/// device is owned by the standard `kvm` group with group read/write bits.
/// We can only build commands once we know the effective username, so a missing
/// username degrades to advisory hints.
fn kvm_permission_problem() -> Problem {
    let device_group = device_group(KVM_DEVICE);
    let user = current_user();
    let process_member = device_group
        .as_ref()
        .map(|group| process_has_group(group.gid))
        .unwrap_or(false);
    let persistent_member = match (&user, &device_group) {
        (Some(user), Some(group)) => persistent_user_in_group(user, group.gid),
        _ => false,
    };

    let cause = match &device_group {
        Some(group) if persistent_member && !process_member => {
            let label = group_label(group);
            format!("you are in the '{label}' group, but this login session predates the change")
        }
        Some(group) if process_member => {
            let label = group_label(group);
            format!(
                "your process belongs to the '{label}' group, but {KVM_DEVICE} still rejects read/write access"
            )
        }
        Some(group) if group.grants_read_write => {
            let label = group_label(group);
            format!("{KVM_DEVICE} is owned by group '{label}', which your user is not in")
        }
        Some(group) => {
            let label = group_label(group);
            format!(
                "{KVM_DEVICE} is owned by group '{label}', but group permissions do not grant read/write access"
            )
        }
        None => format!("your user lacks read/write access to {KVM_DEVICE}"),
    };

    let mut problem = Problem::new(
        format!("{KVM_DEVICE} is not accessible by your user"),
        vec![cause],
    );

    let Some(user) = user else {
        return problem;
    };
    let acl = format!("u:{}:rw", user.name);

    if persistent_member || process_member || !can_offer_group_fix(device_group.as_ref()) {
        // When persistent membership is already present, the direct ACL grants
        // this login session access immediately. For non-standard device groups
        // it is also the only safe automatic mutation; adding users to arbitrary
        // groups can accidentally grant unrelated host privileges.
        problem = problem.with_fix(Fix::new(
            format!(
                "grant {} access to {KVM_DEVICE} for the current session",
                user.name
            ),
            vec![FixCommand::sudo(&[
                "setfacl",
                "-m",
                acl.as_str(),
                KVM_DEVICE,
            ])],
        ));
    } else {
        let group = device_group
            .as_ref()
            .and_then(|group| group.name.as_deref())
            .expect("safe KVM group fixes require a named device group");
        problem = problem.with_fix(
            Fix::new(
                format!(
                    "add {} to the '{group}' group and grant access now",
                    user.name
                ),
                vec![
                    FixCommand::sudo(&["usermod", "-aG", group, user.name.as_str()]),
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

/// Resolve the current effective user's login name and primary group.
fn current_user() -> Option<UserInfo> {
    // SAFETY: getpwuid returns a pointer into a shared static buffer; the doctor
    // command is single-threaded, and we copy the name out immediately.
    unsafe {
        let entry = libc::getpwuid(libc::geteuid());
        if entry.is_null() {
            return None;
        }
        Some(UserInfo {
            name: CStr::from_ptr((*entry).pw_name)
                .to_string_lossy()
                .into_owned(),
            primary_gid: (*entry).pw_gid,
        })
    }
}

/// Resolve the owning group and group permission bits of a device path.
fn device_group(path: &str) -> Option<DeviceGroup> {
    let metadata = std::fs::metadata(path).ok()?;
    let gid = metadata.gid();
    Some(DeviceGroup {
        name: group_name(gid),
        gid,
        grants_read_write: metadata.mode() & 0o060 == 0o060,
    })
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

/// Whether the current process belongs to the given group.
fn process_has_group(gid: libc::gid_t) -> bool {
    if unsafe { libc::getegid() } == gid {
        return true;
    }

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

    gids.into_iter().any(|g| g == gid)
}

/// Whether the user's account is persistently a member of the target group.
fn persistent_user_in_group(user: &UserInfo, gid: libc::gid_t) -> bool {
    user.primary_gid == gid || group_has_member(gid, &user.name)
}

/// Whether a group database entry lists a user as a member.
fn group_has_member(gid: libc::gid_t, user: &str) -> bool {
    // SAFETY: getgrgid returns a pointer into a shared static buffer. We only
    // read the null-terminated member list during this call and copy names into
    // Rust strings before comparing.
    unsafe {
        let entry = libc::getgrgid(gid);
        if entry.is_null() {
            return false;
        }

        let mut member = (*entry).gr_mem;
        while !member.is_null() && !(*member).is_null() {
            if CStr::from_ptr(*member).to_string_lossy() == user {
                return true;
            }
            member = member.add(1);
        }
    }

    false
}

/// Whether it is safe to persist access by adding the user to the device group.
fn can_offer_group_fix(group: Option<&DeviceGroup>) -> bool {
    matches!(
        group,
        Some(DeviceGroup {
            name: Some(name),
            grants_read_write: true,
            ..
        }) if name == "kvm"
    )
}

fn group_label(group: &DeviceGroup) -> String {
    group
        .name
        .clone()
        .unwrap_or_else(|| format!("gid {}", group.gid))
}
