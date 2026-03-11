use crate::backends::passthrough::inode::translate_open_flags;

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

/// Linux O_TRUNC is 0x200, macOS O_TRUNC is 0x400.
/// Without translation, Linux O_TRUNC collides with macOS O_CREAT (0x200).
#[test]
fn test_translate_trunc() {
    let linux_o_trunc: i32 = 0x200;
    let result = translate_open_flags(linux_o_trunc);
    assert!(
        result & libc::O_TRUNC != 0,
        "Linux O_TRUNC (0x200) must map to host O_TRUNC (0x{:x})",
        libc::O_TRUNC,
    );
    // On macOS, must NOT set O_CREAT (which is also 0x200 on macOS).
    #[cfg(target_os = "macos")]
    assert!(
        result & libc::O_CREAT == 0,
        "Linux O_TRUNC must not set macOS O_CREAT",
    );
}

/// Linux O_APPEND is 0x400, macOS O_APPEND is 0x8.
/// Without translation, Linux O_APPEND (0x400) collides with macOS O_TRUNC (0x400).
#[test]
fn test_translate_append() {
    let linux_o_append: i32 = 0x400;
    let result = translate_open_flags(linux_o_append);
    assert!(
        result & libc::O_APPEND != 0,
        "Linux O_APPEND (0x400) must map to host O_APPEND (0x{:x})",
        libc::O_APPEND,
    );
    // On macOS, must NOT set O_TRUNC (which is also 0x400 on macOS).
    #[cfg(target_os = "macos")]
    assert!(
        result & libc::O_TRUNC == 0,
        "Linux O_APPEND must not set macOS O_TRUNC",
    );
}

/// Linux O_CREAT is 0x40, macOS O_CREAT is 0x200.
#[test]
fn test_translate_creat() {
    let linux_o_creat: i32 = 0x40;
    let result = translate_open_flags(linux_o_creat);
    assert!(
        result & libc::O_CREAT != 0,
        "Linux O_CREAT (0x40) must map to host O_CREAT (0x{:x})",
        libc::O_CREAT,
    );
}

/// Linux O_EXCL is 0x80, macOS O_EXCL is 0x800.
#[test]
fn test_translate_excl() {
    let linux_o_excl: i32 = 0x80;
    let result = translate_open_flags(linux_o_excl);
    assert!(
        result & libc::O_EXCL != 0,
        "Linux O_EXCL (0x80) must map to host O_EXCL (0x{:x})",
        libc::O_EXCL,
    );
}

/// Linux O_NOFOLLOW is 0x20000, macOS O_NOFOLLOW is 0x100.
#[test]
fn test_translate_nofollow() {
    let linux_o_nofollow: i32 = 0x20000;
    let result = translate_open_flags(linux_o_nofollow);
    assert!(
        result & libc::O_NOFOLLOW != 0,
        "Linux O_NOFOLLOW (0x20000) must map to host O_NOFOLLOW (0x{:x})",
        libc::O_NOFOLLOW,
    );
}

/// Linux O_NONBLOCK is 0x800, macOS O_NONBLOCK is 0x4.
#[test]
fn test_translate_nonblock() {
    let linux_o_nonblock: i32 = 0x800;
    let result = translate_open_flags(linux_o_nonblock);
    assert!(
        result & libc::O_NONBLOCK != 0,
        "Linux O_NONBLOCK (0x800) must map to host O_NONBLOCK (0x{:x})",
        libc::O_NONBLOCK,
    );
}

/// Linux O_CLOEXEC is 0x80000, macOS O_CLOEXEC is 0x1000000.
#[test]
fn test_translate_cloexec() {
    let linux_o_cloexec: i32 = 0x80000;
    let result = translate_open_flags(linux_o_cloexec);
    assert!(
        result & libc::O_CLOEXEC != 0,
        "Linux O_CLOEXEC (0x80000) must map to host O_CLOEXEC (0x{:x})",
        libc::O_CLOEXEC,
    );
}

/// Linux O_DIRECTORY is 0x10000, macOS O_DIRECTORY is 0x100000.
#[test]
fn test_translate_directory() {
    let linux_o_directory: i32 = 0x10000;
    let result = translate_open_flags(linux_o_directory);
    assert!(
        result & libc::O_DIRECTORY != 0,
        "Linux O_DIRECTORY (0x10000) must map to host O_DIRECTORY (0x{:x})",
        libc::O_DIRECTORY,
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: Combinations
//--------------------------------------------------------------------------------------------------

/// O_RDWR | O_TRUNC | O_CREAT — common create-and-truncate pattern.
#[test]
fn test_translate_rdwr_trunc_creat() {
    let linux_flags: i32 = 2 | 0x200 | 0x40; // O_RDWR | O_TRUNC | O_CREAT
    let result = translate_open_flags(linux_flags);
    assert_eq!(result & 0b11, 2, "access mode should be O_RDWR");
    assert!(result & libc::O_TRUNC != 0, "O_TRUNC must be set");
    assert!(result & libc::O_CREAT != 0, "O_CREAT must be set");
}

/// O_WRONLY | O_APPEND — common append-write pattern.
#[test]
fn test_translate_wronly_append() {
    let linux_flags: i32 = 1 | 0x400; // O_WRONLY | O_APPEND
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
    let linux_flags: i32 = 0x40 | 0x80 | 0x80000; // O_CREAT | O_EXCL | O_CLOEXEC
    let result = translate_open_flags(linux_flags);
    assert!(result & libc::O_CREAT != 0, "O_CREAT must be set");
    assert!(result & libc::O_EXCL != 0, "O_EXCL must be set");
    assert!(result & libc::O_CLOEXEC != 0, "O_CLOEXEC must be set");
}

/// All flags combined — no flags should be dropped or collide.
#[test]
fn test_translate_all_flags() {
    let linux_flags: i32 = 2        // O_RDWR
        | 0x400   // O_APPEND
        | 0x40    // O_CREAT
        | 0x200   // O_TRUNC
        | 0x80    // O_EXCL
        | 0x20000 // O_NOFOLLOW
        | 0x800   // O_NONBLOCK
        | 0x80000 // O_CLOEXEC
        | 0x10000; // O_DIRECTORY
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

/// Unknown bits (not in the translation table) should be silently dropped,
/// not passed through as garbage host flags.
#[test]
fn test_translate_unknown_bits_dropped() {
    // 0x1000 is not a translated Linux flag (it's Linux O_DSYNC on some arches).
    let linux_flags: i32 = 0x1000;
    let result = translate_open_flags(linux_flags);
    // On Linux, identity — fine to pass through.
    // On macOS, should be 0 (only access mode bits, which are 0 = O_RDONLY).
    #[cfg(target_os = "macos")]
    assert_eq!(
        result, 0,
        "untranslated Linux bits must not leak through on macOS"
    );
}
