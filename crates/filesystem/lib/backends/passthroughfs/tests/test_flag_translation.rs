use crate::backends::passthroughfs::inode::translate_open_flags;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LINUX_O_CREAT: i32 = 0x40;
const LINUX_O_EXCL: i32 = 0x80;
const LINUX_O_TRUNC: i32 = 0x200;
const LINUX_O_APPEND: i32 = 0x400;
const LINUX_O_NONBLOCK: i32 = 0x800;
const LINUX_O_CLOEXEC: i32 = 0x80000;
#[cfg(target_os = "linux")]
const LINUX_FMODE_EXEC: i32 = 0x20;

#[cfg(target_os = "linux")]
const LINUX_O_NOFOLLOW: i32 = libc::O_NOFOLLOW;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const LINUX_O_NOFOLLOW: i32 = 0x20000;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const LINUX_O_NOFOLLOW: i32 = 0x8000;

#[cfg(target_os = "linux")]
const LINUX_O_DIRECTORY: i32 = libc::O_DIRECTORY;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const LINUX_O_DIRECTORY: i32 = 0x10000;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const LINUX_O_DIRECTORY: i32 = 0x4000;

//--------------------------------------------------------------------------------------------------
// Tests: Identity (access mode bits are same on both platforms)
//--------------------------------------------------------------------------------------------------

#[test]
fn test_translate_rdonly() {
    let result = translate_open_flags(0); // O_RDONLY = 0 on both platforms
    assert_eq!(result & 0b11, 0, "O_RDONLY should be 0");
}

#[test]
fn test_translate_wronly() {
    let result = translate_open_flags(1); // O_WRONLY = 1 on both platforms
    assert_eq!(result & 0b11, 1, "O_WRONLY should be 1");
}

#[test]
fn test_translate_rdwr() {
    let result = translate_open_flags(2); // O_RDWR = 2 on both platforms
    assert_eq!(result & 0b11, 2, "O_RDWR should be 2");
}

//--------------------------------------------------------------------------------------------------
// Tests: Flag mapping (Linux numeric values → host libc constants)
//--------------------------------------------------------------------------------------------------

/// Linux O_TRUNC collides with macOS O_CREAT if we skip translation.
#[test]
fn test_translate_trunc() {
    let result = translate_open_flags(LINUX_O_TRUNC);
    assert!(
        result & libc::O_TRUNC != 0,
        "Linux O_TRUNC (0x{:x}) must map to host O_TRUNC (0x{:x})",
        LINUX_O_TRUNC,
        libc::O_TRUNC,
    );
    // On macOS, must NOT set O_CREAT (which is also 0x200 on macOS).
    #[cfg(target_os = "macos")]
    assert!(
        result & libc::O_CREAT == 0,
        "Linux O_TRUNC must not set macOS O_CREAT",
    );
}

/// Linux O_APPEND collides with macOS O_TRUNC if we skip translation.
#[test]
fn test_translate_append() {
    let result = translate_open_flags(LINUX_O_APPEND);
    assert!(
        result & libc::O_APPEND != 0,
        "Linux O_APPEND (0x{:x}) must map to host O_APPEND (0x{:x})",
        LINUX_O_APPEND,
        libc::O_APPEND,
    );
    // On macOS, must NOT set O_TRUNC (which is also 0x400 on macOS).
    #[cfg(target_os = "macos")]
    assert!(
        result & libc::O_TRUNC == 0,
        "Linux O_APPEND must not set macOS O_TRUNC",
    );
}

#[test]
fn test_translate_creat() {
    let result = translate_open_flags(LINUX_O_CREAT);
    assert!(
        result & libc::O_CREAT != 0,
        "Linux O_CREAT (0x{:x}) must map to host O_CREAT (0x{:x})",
        LINUX_O_CREAT,
        libc::O_CREAT,
    );
}

#[test]
fn test_translate_excl() {
    let result = translate_open_flags(LINUX_O_EXCL);
    assert!(
        result & libc::O_EXCL != 0,
        "Linux O_EXCL (0x{:x}) must map to host O_EXCL (0x{:x})",
        LINUX_O_EXCL,
        libc::O_EXCL,
    );
}

/// Linux O_NOFOLLOW differs across guest architectures and must survive translation.
#[test]
fn test_translate_nofollow() {
    let result = translate_open_flags(LINUX_O_NOFOLLOW);
    assert!(
        result & libc::O_NOFOLLOW != 0,
        "Linux O_NOFOLLOW (0x{:x}) must map to host O_NOFOLLOW (0x{:x})",
        LINUX_O_NOFOLLOW,
        libc::O_NOFOLLOW,
    );
}

#[test]
fn test_translate_nonblock() {
    let result = translate_open_flags(LINUX_O_NONBLOCK);
    assert!(
        result & libc::O_NONBLOCK != 0,
        "Linux O_NONBLOCK (0x{:x}) must map to host O_NONBLOCK (0x{:x})",
        LINUX_O_NONBLOCK,
        libc::O_NONBLOCK,
    );
}

#[test]
fn test_translate_cloexec() {
    let result = translate_open_flags(LINUX_O_CLOEXEC);
    assert!(
        result & libc::O_CLOEXEC != 0,
        "Linux O_CLOEXEC (0x{:x}) must map to host O_CLOEXEC (0x{:x})",
        LINUX_O_CLOEXEC,
        libc::O_CLOEXEC,
    );
}

/// Linux O_DIRECTORY differs across guest architectures and must survive translation.
#[test]
fn test_translate_directory() {
    let result = translate_open_flags(LINUX_O_DIRECTORY);
    assert!(
        result & libc::O_DIRECTORY != 0,
        "Linux O_DIRECTORY (0x{:x}) must map to host O_DIRECTORY (0x{:x})",
        LINUX_O_DIRECTORY,
        libc::O_DIRECTORY,
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: Combinations
//--------------------------------------------------------------------------------------------------

/// O_RDWR | O_TRUNC | O_CREAT — common create-and-truncate pattern.
#[test]
fn test_translate_rdwr_trunc_creat() {
    let linux_flags: i32 = 2 | LINUX_O_TRUNC | LINUX_O_CREAT;
    let result = translate_open_flags(linux_flags);
    assert_eq!(result & 0b11, 2, "access mode should be O_RDWR");
    assert!(result & libc::O_TRUNC != 0, "O_TRUNC must be set");
    assert!(result & libc::O_CREAT != 0, "O_CREAT must be set");
}

/// O_WRONLY | O_APPEND — common append-write pattern.
#[test]
fn test_translate_wronly_append() {
    let linux_flags: i32 = 1 | LINUX_O_APPEND;
    let result = translate_open_flags(linux_flags);
    assert_eq!(result & 0b11, 1, "access mode should be O_WRONLY");
    assert!(result & libc::O_APPEND != 0, "O_APPEND must be set");
    // Must not accidentally set O_TRUNC.
    #[cfg(target_os = "macos")]
    assert!(
        result & libc::O_TRUNC == 0,
        "O_APPEND must not leak into O_TRUNC"
    );
}

/// O_CREAT | O_EXCL | O_CLOEXEC — exclusive create with close-on-exec.
#[test]
fn test_translate_creat_excl_cloexec() {
    let linux_flags: i32 = LINUX_O_CREAT | LINUX_O_EXCL | LINUX_O_CLOEXEC;
    let result = translate_open_flags(linux_flags);
    assert!(result & libc::O_CREAT != 0, "O_CREAT must be set");
    assert!(result & libc::O_EXCL != 0, "O_EXCL must be set");
    assert!(result & libc::O_CLOEXEC != 0, "O_CLOEXEC must be set");
}

/// All flags combined — no flags should be dropped or collide.
#[test]
fn test_translate_all_flags() {
    let linux_flags: i32 = 2        // O_RDWR
        | LINUX_O_APPEND
        | LINUX_O_CREAT
        | LINUX_O_TRUNC
        | LINUX_O_EXCL
        | LINUX_O_NOFOLLOW
        | LINUX_O_NONBLOCK
        | LINUX_O_CLOEXEC
        | LINUX_O_DIRECTORY;
    let result = translate_open_flags(linux_flags);
    assert_eq!(result & 0b11, 2);
    assert!(result & libc::O_APPEND != 0);
    assert!(result & libc::O_CREAT != 0);
    assert!(result & libc::O_TRUNC != 0);
    assert!(result & libc::O_EXCL != 0);
    assert!(result & libc::O_NOFOLLOW != 0);
    assert!(result & libc::O_NONBLOCK != 0);
    assert!(result & libc::O_CLOEXEC != 0);
    assert!(result & libc::O_DIRECTORY != 0);
}

/// Kernel-internal FUSE exec bits must not leak into host open flags.
#[test]
fn test_translate_kernel_exec_bit_dropped() {
    #[cfg(target_os = "linux")]
    assert_eq!(
        translate_open_flags(LINUX_FMODE_EXEC),
        0,
        "Linux hosts must strip FMODE_EXEC from guest open requests"
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        translate_open_flags(0x20),
        0,
        "untranslated Linux bits must not leak through on macOS"
    );
}
