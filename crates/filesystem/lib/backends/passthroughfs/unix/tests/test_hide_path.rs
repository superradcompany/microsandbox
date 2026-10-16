//! Tests for the bind-mount hide_path-list enforcement.

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: component-only pattern (basename) matching
//--------------------------------------------------------------------------------------------------

/// A denied basename is invisible via lookup.
#[test]
fn test_hide_path_basename_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"secret");
    sb.host_create_file("visible.txt", b"ok");

    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);

    // Non-denied file still works.
    let entry = sb.lookup_root("visible.txt").unwrap();
    assert_ne!(entry.inode, 0);
}

//--------------------------------------------------------------------------------------------------
// Tests: case-sensitivity follows the host mount capability
//--------------------------------------------------------------------------------------------------

/// Deny matching follows the host's actual case capability: on a case-sensitive
/// mount `.env` does not hide a differently-cased `.ENV` (the host treats them as
/// distinct files, so over-folding would wrongly hide a legitimate file), while on
/// a case-insensitive mount the pattern folds and hides it.
///
/// The expectation is derived from the mount probe instead of assuming a
/// case-sensitive temp dir: default APFS/HFS+ (macOS) and FAT are
/// case-insensitive, so a hard-coded expectation fails on those hosts.
#[test]
fn test_hide_path_case_variant_matches_host_case_capability() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".ENV", b"case variant");

    if sb.fs.hide_path.default_case_insensitive() {
        // The mount folds case, so `.ENV` and `.env` are the same file and the
        // denied basename hides it.
        TestSandbox::assert_errno(sb.lookup_root(".ENV"), LINUX_ENOENT);
    } else {
        let entry = sb.lookup_root(".ENV");
        assert!(
            entry.is_ok(),
            "case-sensitive host must not fold a denied basename over a distinct file"
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: a path pattern folds with the case of every directory it crosses
//--------------------------------------------------------------------------------------------------

/// A path pattern must match a differently-cased component whose containing
/// directory folds case, even when a deeper directory is case-sensitive. On a
/// case-sensitive mount root, `fold` carries `FS_CASEFOLD_FL`, so the guest
/// resolves `fold/data` to `fold/Data`; a hide_path path `fold/data/secret` must still
/// hide the file once `fold`'s fold is known.
///
/// Linux-only: the test seeds the per-directory `FS_CASEFOLD_FL` cache through
/// `InodeData::case_insensitive`, which exists only on Linux.
#[test]
#[cfg(target_os = "linux")]
fn test_hide_path_path_pattern_folds_with_ancestor_directory() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["fold/data/secret".to_string()],
        // A path pattern is only admitted on a read-only mount.
        readonly: true,
        ..cfg
    });
    sb.host_create_file("fold/Data/secret", b"hidden");

    let fold = sb.fs.lookup(sb.ctx(), ROOT_INODE, c"fold").unwrap().inode;
    let data = sb.fs.lookup(sb.ctx(), fold, c"Data").unwrap().inode;

    // With `fold` treated as case-sensitive (its real flag unknown here), the
    // differently-cased intermediate component does not match.
    assert!(
        sb.fs.lookup(sb.ctx(), data, c"secret").is_ok(),
        "a case-sensitive ancestor must not fold an intermediate path component"
    );

    // Simulate `FS_CASEFOLD_FL` on `fold`: the same lookup must now be denied.
    {
        let inodes = sb.fs.inodes.read().unwrap();
        inodes.get(&fold).unwrap().case_insensitive.store(
            crate::backends::passthroughfs::hide_path::CASE_INSENSITIVE,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    TestSandbox::assert_errno(sb.fs.lookup(sb.ctx(), data, c"secret"), LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: structural `.`/`..` entries are never denied
//--------------------------------------------------------------------------------------------------

/// A `.*` pattern must not strip the structural `.` and `..` entries from
/// readdir, otherwise path walks break.
#[test]
fn test_hide_path_star_pattern_keeps_dot_and_dotdot() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".*".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"secret");
    sb.host_create_file("visible.txt", b"ok");

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 4096, 0)
        .unwrap();

    let names: Vec<&[u8]> = entries.iter().map(|e| &e.name[..]).collect();
    assert!(
        names.contains(&b".".as_slice()),
        "readdir must still contain '.' under a '.*' hide-path pattern"
    );
    assert!(
        names.contains(&b"..".as_slice()),
        "readdir must still contain '..' under a '.*' hide-path pattern"
    );
    assert!(
        !names.contains(&b".env".as_slice()),
        ".env should be hidden by the '.*' hide-path pattern"
    );
}

/// `lookup(".")` must resolve to the parent directory, not be denied by a
/// `.*` or `*` pattern.
#[test]
fn test_hide_path_star_pattern_lookup_dot_succeeds() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".*".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/data.txt", b"ok");

    // lookup(".") in root and in a subdir must succeed.
    let root_dot = sb.lookup(ROOT_INODE, ".").unwrap();
    assert_eq!(root_dot.inode, ROOT_INODE);

    let sub = sb.lookup(ROOT_INODE, "sub").unwrap();
    let sub_dot = sb.lookup(sub.inode, ".").unwrap();
    assert_eq!(sub_dot.inode, sub.inode);

    // And a path walk through a subdirectory still works.
    let data = sb.lookup(sub.inode, "data.txt").unwrap();
    assert_ne!(data.inode, 0);
}

//--------------------------------------------------------------------------------------------------
// Tests: create/mkdir EACCES on denied names
//--------------------------------------------------------------------------------------------------

/// Creating a denied basename via FUSE returns EACCES.
#[test]
fn test_hide_path_create_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".secrets".to_string()],
        ..cfg
    });

    TestSandbox::assert_errno(sb.fuse_create_root(".secrets"), LINUX_EACCES);

    // Normal create still works.
    let (entry, _handle) = sb.fuse_create_root("normal.txt").unwrap();
    assert_ne!(entry.inode, 0);
}

/// Creating a hidden directory returns EACCES from the hide-path list.
#[test]
fn test_hide_path_mkdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".hidden_dir".to_string(), "no_create.txt".to_string()],
        ..cfg
    });

    TestSandbox::assert_errno(sb.fuse_mkdir_root(".hidden_dir"), LINUX_EACCES);

    // Normal dirs work.
    sb.fuse_mkdir_root("visible_dir").unwrap();
    sb.lookup_root("visible_dir").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: rename EACCES on denied names
//--------------------------------------------------------------------------------------------------

/// Renaming a denied source name away returns EACCES.
#[test]
fn test_hide_path_rename_from_denied_source() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".forbidden".to_string()],
        ..cfg
    });

    // A denied name already exists on the host.
    sb.host_create_file(".forbidden", b"hidden");

    // Renaming it away is rejected.
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr(".forbidden"),
            ROOT_INODE,
            &TestSandbox::cstr("freed.txt"),
            0,
        ),
        LINUX_EACCES,
    );
}

/// Renaming into a denied target name returns EACCES.
#[test]
fn test_hide_path_rename_to_denied_target() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".forbidden".to_string()],
        ..cfg
    });

    // Create a source file first.
    let (_entry, _handle) = sb.fuse_create_root("source.txt").unwrap();

    // Rename to denied name.
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("source.txt"),
            ROOT_INODE,
            &TestSandbox::cstr(".forbidden"),
            0,
        ),
        LINUX_EACCES,
    );

    // Rename to normal name still works.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("source.txt"),
            ROOT_INODE,
            &TestSandbox::cstr("renamed.txt"),
            0,
        )
        .unwrap();
    sb.lookup_root("renamed.txt").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: readdir filtering
//--------------------------------------------------------------------------------------------------

/// PROOF (H1): a readdir request whose `nodeid` disagrees with the handle's
/// inode must not leak path-pattern-denied entries; the hide_path path must come from
/// the handle's inode, not the request. Fails on the unpatched backend.
#[test]
fn test_hide_path_readdir_ignores_mismatched_request_inode() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["a/.env".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("a");
    sb.host_create_file("a/.env", b"hidden");
    sb.host_create_file("a/ok.txt", b"ok");

    let a = sb.lookup_root("a").unwrap().inode;

    // Correct nodeid: the path pattern hides `.env`.
    let correct = sb.fuse_opendir(a).unwrap();
    let correct_entries = sb.fs.readdir(sb.ctx(), a, correct, 4096, 0).unwrap();
    assert!(
        !correct_entries.iter().any(|e| e.name == b".env"),
        "hide_path path pattern must hide `.env` under the real directory"
    );

    // Same directory handle, mismatched request nodeid: rejected (not leaked).
    let mismatched = sb.fuse_opendir(a).unwrap();
    match sb.fs.readdir(sb.ctx(), ROOT_INODE, mismatched, 4096, 0) {
        Err(err) => assert_eq!(
            err.raw_os_error(),
            Some(LINUX_EBADF),
            "mismatched nodeid must be rejected as EBADF"
        ),
        Ok(leaked) => {
            let leaked_names: Vec<String> = leaked
                .iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect();
            panic!("readdir leaked entries via a mismatched nodeid: {leaked_names:?}");
        }
    }
}

/// Denied entries are omitted from readdir.
#[test]
fn test_hide_path_readdir_omits_entries() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string(), "*.log".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"hidden");
    sb.host_create_file("data.log", b"hidden");
    sb.host_create_file("visible.txt", b"ok");

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 4096, 0)
        .unwrap();

    let has_env = entries.iter().any(|e| e.name == b".env");
    let has_log = entries.iter().any(|e| e.name == b"data.log");
    let has_visible = entries.iter().any(|e| e.name == b"visible.txt");

    assert!(!has_env, ".env should be hidden from readdir");
    assert!(!has_log, "data.log should be hidden from readdir");
    assert!(has_visible, "visible.txt should be in readdir");
}

/// Denied entries are omitted from readdirplus too.
#[test]
fn test_hide_path_readdirplus_omits_entries() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string(), "*.log".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"hidden");
    sb.host_create_file("data.log", b"hidden");
    sb.host_create_file("visible.txt", b"ok");

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdirplus(sb.ctx(), ROOT_INODE, handle, 65536, 0)
        .unwrap();

    let names: Vec<&[u8]> = entries.iter().map(|(de, _)| de.name).collect();
    assert!(
        !names.contains(&b".env".as_slice()),
        ".env should be hidden from readdirplus"
    );
    assert!(
        !names.contains(&b"data.log".as_slice()),
        "data.log should be hidden from readdirplus"
    );
    assert!(names.contains(&b"visible.txt".as_slice()));
}

//--------------------------------------------------------------------------------------------------
// Tests: unlink/rmdir EACCES
//--------------------------------------------------------------------------------------------------

/// Unlink of a denied name returns EACCES.
#[test]
fn test_hide_path_unlink_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".do-not-delete".to_string()],
        ..cfg
    });

    sb.host_create_file(".do-not-delete", b"protected");
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".do-not-delete")),
        LINUX_EACCES,
    );
}

/// Rmdir of a denied directory returns EACCES.
#[test]
fn test_hide_path_rmdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".protected-dir".to_string()],
        ..cfg
    });

    sb.host_create_dir(".protected-dir");
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr(".protected-dir")),
        LINUX_EACCES,
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: non-denied operations unaffected
//--------------------------------------------------------------------------------------------------

/// Non-denied names remain fully read-write.
#[test]
fn test_hide_path_normal_ops_unchanged() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string()],
        ..cfg
    });

    // Create, write, read all work on non-denied names.
    let (entry, handle) = sb.fuse_create_root("writeable.txt").unwrap();
    let written = sb
        .fuse_write(entry.inode, handle, b"hello path", 0)
        .unwrap();
    assert_eq!(written, 10);

    let (handle, _) = sb
        .fs
        .open(sb.ctx(), entry.inode, false, LINUX_O_RDWR)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle.unwrap(), 10, 0).unwrap();
    assert_eq!(data, b"hello path");

    // Unlink works on normal files.
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("writeable.txt"))
        .unwrap();

    // After unlink, lookup returns ENOENT.
    TestSandbox::assert_errno(sb.lookup_root("writeable.txt"), LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: path-pattern (nested) matching
//--------------------------------------------------------------------------------------------------

/// A nested path pattern hides the matching path but not its siblings.
#[test]
fn test_hide_path_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/.env".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/.env", b"secret");
    sb.host_create_file("sub/visible.txt", b"ok");

    // The parent dir is reachable.
    let dir = sb.lookup_root("sub").unwrap();
    assert_ne!(dir.inode, 0);

    // The denied nested file is hidden.
    TestSandbox::assert_errno(sb.lookup(dir.inode, ".env"), LINUX_ENOENT);

    // A sibling in the same dir is visible.
    let visible = sb.lookup(dir.inode, "visible.txt").unwrap();
    assert_ne!(visible.inode, 0);
}

/// A recursive path pattern hides nested matches at any depth.
#[test]
fn test_hide_path_recursive_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["**/env.secret".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("a");
    sb.host_create_file("a/env.secret", b"secret");
    sb.host_create_dir("a/b");
    sb.host_create_file("a/b/env.secret", b"secret");

    let a = sb.lookup_root("a").unwrap();
    TestSandbox::assert_errno(sb.lookup(a.inode, "env.secret"), LINUX_ENOENT);
    let b = sb.lookup(a.inode, "b").unwrap();
    TestSandbox::assert_errno(sb.lookup(b.inode, "env.secret"), LINUX_ENOENT);
}

/// A path pattern on a writable mount is refused by the backend constructor.
///
/// The per-operation create check for path patterns is therefore unreachable
/// with a writable mount; the hide_path matcher itself is covered by the readonly
/// lookup and readdir tests. Here we pin that `PassthroughFs::new` (not just
/// the builder) enforces the rule.
#[test]
fn test_hide_path_path_pattern_create() {
    let tmp = tempfile::tempdir().unwrap();

    let writable = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        hide_path: vec![".sub/.secret".to_string()],
        ..Default::default()
    });
    assert!(
        writable.is_err(),
        "a writable mount must refuse a path pattern"
    );

    let readonly = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        hide_path: vec![".sub/.secret".to_string()],
        readonly: true,
        ..Default::default()
    });
    assert!(
        readonly.is_ok(),
        "a read-only mount must accept a path pattern"
    );
}

/// A path pattern is only valid on a read-only mount, where the guest cannot
/// rename an ancestor directory to launder the denied path. The rename itself
/// is refused outright (`EROFS`), so the writable laundering path is closed.
///
/// This replaces the previous writable-mount expectation: a path pattern is now
/// rejected at construction on a writable mount (see
/// `builder_rejects_path_pattern_on_writable_mount`).
#[test]
fn test_hide_path_path_pattern_rename_onto_denied_path_is_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/.env".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("src", b"x");

    let sub = sb.lookup_root("sub").unwrap();

    // A rename would let a writable guest launder the location, so a read-only
    // mount refuses the rename entirely.
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src"),
            sub.inode,
            &TestSandbox::cstr(".env"),
            0,
        ),
        LINUX_EROFS,
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: dir-only patterns (trailing `/`, e.g. `node_modules/`)
//--------------------------------------------------------------------------------------------------

/// A dir-only pattern hides a directory on lookup.
#[test]
fn test_hide_path_dir_only_lookup_hides_directory() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_dir("node_modules");
    sb.host_create_dir("visible_dir");

    // A directory named node_modules is hidden.
    TestSandbox::assert_errno(sb.lookup_root("node_modules"), LINUX_ENOENT);
    assert_ne!(sb.lookup_root("visible_dir").unwrap().inode, 0);
}

/// A dir-only pattern does not hide a same-named file on lookup.
#[test]
fn test_hide_path_dir_only_lookup_serves_same_named_file() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_file("node_modules", b"not a dir");

    // A file named node_modules is served (gitignore 'foo/' does not match files).
    let entry = sb.lookup_root("node_modules").unwrap();
    assert_ne!(entry.inode, 0);
}

/// A dir-only path pattern is decided from the opened entry, so under an active
/// path pattern it still hides the directory and spares a same-named file
/// outside the pattern's path.
#[test]
fn test_hide_path_dir_only_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/node_modules/".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_dir("sub/node_modules");
    sb.host_create_dir("other");
    sb.host_create_file("other/node_modules", b"not a dir");

    let sub = sb.lookup_root("sub").unwrap();
    TestSandbox::assert_errno(sb.lookup(sub.inode, "node_modules"), LINUX_ENOENT);

    // The same-named file outside the pattern's path is served.
    let other = sb.lookup_root("other").unwrap();
    assert_ne!(sb.lookup(other.inode, "node_modules").unwrap().inode, 0);
}

/// A dir-only pattern allows creating a same-named file but rejects mkdir.
#[test]
fn test_hide_path_dir_only_mkdir_rejected_but_file_create_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    // mkdir of a denied directory name is rejected.
    TestSandbox::assert_errno(sb.fuse_mkdir_root("node_modules"), LINUX_EACCES);

    // A same-named file create is allowed (gitignore 'foo/' does not match files).
    let (entry, _handle) = sb.fuse_create_root("node_modules").unwrap();
    assert_ne!(entry.inode, 0);

    // And a different directory name is allowed.
    sb.fuse_mkdir_root("other_dir").unwrap();
}

/// A dir-only pattern omits a directory from readdir but keeps a same-named
/// file: `node_modules/` matches directories only, so a file named
/// `node_modules` stays visible.
#[test]
fn test_hide_path_dir_only_readdir_keeps_same_named_file() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_dir("node_modules");
    sb.host_create_dir("visible_dir");
    sb.host_create_file("visible.txt", b"ok");
    // A same-named *file* in a subdirectory must stay visible.
    sb.host_create_dir("sub");
    sb.host_create_file("sub/node_modules", b"not a dir");

    let handle = sb.fuse_opendir(ROOT_INODE).unwrap();
    let entries = sb
        .fs
        .readdir(sb.ctx(), ROOT_INODE, handle, 4096, 0)
        .unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| &e.name[..]).collect();

    assert!(
        !names.contains(&b"node_modules".as_slice()),
        "directory node_modules should be hidden from readdir by 'node_modules/'"
    );
    assert!(names.contains(&b"visible_dir".as_slice()));
    assert!(names.contains(&b"visible.txt".as_slice()));

    // The same-named file one level down is kept.
    let sub = sb.lookup_root("sub").unwrap();
    let sub_handle = sb.fuse_opendir(sub.inode).unwrap();
    let sub_entries = sb
        .fs
        .readdir(sb.ctx(), sub.inode, sub_handle, 4096, 0)
        .unwrap();
    let sub_names: Vec<&[u8]> = sub_entries.iter().map(|e| &e.name[..]).collect();
    assert!(
        sub_names.contains(&b"node_modules".as_slice()),
        "a file named node_modules must not be hidden by 'node_modules/'"
    );
}

/// A dir-only pattern rejects renaming a directory to the denied name but
/// allows renaming a same-named file there.
#[test]
fn test_hide_path_dir_only_rename_dir_rejected_file_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    // A source directory cannot be renamed to the denied name.
    sb.fuse_mkdir_root("src_dir").unwrap();
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src_dir"),
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
            0,
        ),
        LINUX_EACCES,
    );

    // A source file CAN be renamed to the denied name (it becomes a file, not a dir).
    let (_entry, _handle) = sb.fuse_create_root("src_file").unwrap();
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src_file"),
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
            0,
        )
        .unwrap();
    // It is now a file named node_modules and remains visible.
    let entry = sb.lookup_root("node_modules").unwrap();
    assert_ne!(entry.inode, 0);
}

/// Renaming a file over an already-hidden directory returns EACCES, not the
/// raw EISDIR the syscall would otherwise surface (which would leak the hidden
/// entry's existence and type).
#[test]
fn test_hide_path_dir_only_rename_file_over_hidden_dir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    sb.host_create_dir("node_modules");
    let (_entry, _handle) = sb.fuse_create_root("src_file").unwrap();

    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src_file"),
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
            0,
        ),
        LINUX_EACCES,
    );
}

/// RENAME_EXCHANGE also moves the destination onto the *source* name, so a
/// file exchanged with an allowed directory would land the directory at a
/// dir-only-denied source name. The reverse direction must be rejected.
#[test]
fn test_hide_path_dir_only_rename_exchange_dir_onto_denied_name_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    // A file named `node_modules` is allowed under 'node_modules/'; a dir at
    // an allowed name is allowed. Exchanging them must not be.
    let (_entry, _handle) = sb.fuse_create_root("node_modules").unwrap();
    sb.fuse_mkdir_root("staging").unwrap();

    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
            ROOT_INODE,
            &TestSandbox::cstr("staging"),
            2, // RENAME_EXCHANGE
        ),
        LINUX_EACCES,
    );

    // The layout is unchanged: the file is still visible, the dir stayed put.
    let entry = sb.lookup_root("node_modules").unwrap();
    assert_ne!(entry.inode, 0);
    sb.lookup_root("staging").unwrap();
}

/// RENAME_EXCHANGE of two files keeps files on both sides, so a dir-only
/// pattern does not apply even when one name matches it.
#[test]
fn test_hide_path_dir_only_rename_exchange_two_files_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    let (_entry, _handle) = sb.fuse_create_root("node_modules").unwrap();
    let (_entry2, _handle2) = sb.fuse_create_root("allowed.txt").unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
            ROOT_INODE,
            &TestSandbox::cstr("allowed.txt"),
            2, // RENAME_EXCHANGE
        )
        .unwrap();

    // Both names still resolve: node_modules holds a file, which stays visible.
    sb.lookup_root("node_modules").unwrap();
    sb.lookup_root("allowed.txt").unwrap();
}

/// RENAME_EXCHANGE of two directories at allowed names passes the dir-only
/// checks: neither endpoint is denied, so the destination identity re-check
/// must not block the swap.
#[test]
fn test_hide_path_dir_only_rename_exchange_two_dirs_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    sb.fuse_mkdir_root("one").unwrap();
    sb.fuse_mkdir_root("two").unwrap();

    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("one"),
            ROOT_INODE,
            &TestSandbox::cstr("two"),
            2, // RENAME_EXCHANGE
        )
        .unwrap();

    sb.lookup_root("one").unwrap();
    sb.lookup_root("two").unwrap();
}

/// Renaming a directory onto an already-hidden file returns EACCES.
///
/// A basename pattern such as `.env` matches both files and directories, so
/// this is caught by the source-type check (`source_is_dir = true`) rather
/// than leaking the hidden file's existence through a raw ENOTDIR.
#[test]
fn test_hide_path_rename_dir_over_hidden_file_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string()],
        ..cfg
    });

    sb.host_create_file(".env", b"secret");
    sb.fuse_mkdir_root("src_dir").unwrap();

    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src_dir"),
            ROOT_INODE,
            &TestSandbox::cstr(".env"),
            0,
        ),
        LINUX_EACCES,
    );
}

/// A dir-only pattern rejects rmdir of the denied directory.
#[test]
fn test_hide_path_dir_only_rmdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    sb.host_create_dir("node_modules");
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("node_modules")),
        LINUX_EACCES,
    );
}

/// A dir-only pattern must hide the directory from `unlink` too: otherwise the
/// raw unlink returns EISDIR, revealing that a hidden name exists and is a
/// directory (an existence/type oracle).
#[test]
fn test_hide_path_dir_only_unlink_dir_rejected_not_eisdir() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    sb.host_create_dir("node_modules");
    TestSandbox::assert_errno(
        sb.fs
            .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("node_modules")),
        LINUX_EACCES,
    );
    // The name stays fully hidden.
    TestSandbox::assert_errno(sb.lookup_root("node_modules"), LINUX_ENOENT);
}

/// A dir-only pattern allows unlink of a same-named file (gitignore 'foo/'
/// does not match files).
#[test]
fn test_hide_path_dir_only_unlink_same_named_file_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });

    let (_entry, _handle) = sb.fuse_create_root("node_modules").unwrap();
    sb.fs
        .unlink(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("node_modules"))
        .unwrap();
    TestSandbox::assert_errno(sb.lookup_root("node_modules"), LINUX_ENOENT);
}

/// A path pattern must fail closed when the parent inode cannot be resolved.
#[test]
fn test_hide_path_path_pattern_fails_closed_on_unresolvable_parent() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/.env".to_string()],
        readonly: true,
        ..cfg
    });

    // A bogus parent inode is absent from the inode table, so its path cannot
    // be reconstructed. With active path patterns this must hide_path, never allow.
    assert!(
        sb.fs.hide_path_matches_name(1_000_000, b"secret", false),
        "unresolvable parent under path patterns must fail closed"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: backend boundary rejects writable-mount path patterns
//--------------------------------------------------------------------------------------------------

/// The backend boundary refuses a path pattern on a writable mount, matching
/// the SDK/runtime rule, so a caller reaching the builder directly cannot
/// bypass it. A read-only mount accepts the same pattern.
#[test]
fn builder_rejects_path_pattern_on_writable_mount() {
    let tmp = tempfile::tempdir().unwrap();

    let writable = PassthroughFs::builder()
        .root_dir(tmp.path())
        .hide_path(["sub/.env".to_string()])
        .build();
    assert!(
        writable.is_err(),
        "a writable mount must reject a path pattern"
    );

    let readonly = PassthroughFs::builder()
        .root_dir(tmp.path())
        .readonly(true)
        .hide_path(["sub/.env".to_string()])
        .build();
    assert!(
        readonly.is_ok(),
        "a read-only mount must accept a path pattern"
    );

    // Name-only patterns stay valid on a writable mount.
    let name_only = PassthroughFs::builder()
        .root_dir(tmp.path())
        .hide_path([".env".to_string(), "node_modules/".to_string()])
        .build();
    assert!(name_only.is_ok(), "name-only patterns are always writable");
}

//--------------------------------------------------------------------------------------------------
// Tests: rename hide_path decision helper (both Retry branches)
//--------------------------------------------------------------------------------------------------

/// Directly exercises `decide_rename_hide_path`: a fresh source identity proceeds, a
/// stale one retries, and a denied endpoint is denied. Covers the extraction's
/// Proceed/Retry/Deny branches without needing a concurrent writer (or macOS).
///
/// The exchange-destination `Retry` re-check inside one call cannot be exercised
/// end-to-end without a concurrent writer mutating the destination between the
/// capture and the re-check (the two reads happen back-to-back in the same
/// call). Its predicate — `ExchangeDest::still_matches` — is asserted directly
/// below and also covered by the unit tests in `remove_ops`.
#[test]
fn test_decide_rename_hide_path_proceeds_and_retries_on_stale_source() {
    use super::super::inode;
    use super::super::remove_ops::{
        ExchangeDest, RenameDecision, RenameEndpoint, decide_rename_hide_path,
    };
    use crate::backends::shared::platform;

    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["sub/.env".to_string()],
        readonly: true,
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/keep", b"x");

    let sub_inode = sb.lookup_root("sub").unwrap().inode;
    let keep_inode = sb.lookup(sub_inode, "keep").unwrap().inode;

    let sub_fd = inode::get_inode_fd(&sb.fs, sub_inode).unwrap();
    let keep_fd = inode::get_inode_fd(&sb.fs, keep_inode).unwrap();

    let keep_name = TestSandbox::cstr("keep");
    let dest_name = TestSandbox::cstr("keep2");
    let old = RenameEndpoint {
        fd: &sub_fd,
        dir: sub_inode,
        name: keep_name.as_c_str(),
    };
    let new = RenameEndpoint {
        fd: &sub_fd,
        dir: sub_inode,
        name: dest_name.as_c_str(),
    };

    // Fresh source identity -> proceed (`sub/.env` does not match `sub/keep`).
    let current = platform::fstat(keep_fd.raw()).unwrap();
    assert!(matches!(
        decide_rename_hide_path(&sb.fs, old, new, 0, &current).unwrap(),
        RenameDecision::Proceed
    ));

    // A stale captured identity (the parent directory's) -> retry.
    let stale = platform::fstat(sub_fd.raw()).unwrap();
    assert!(matches!(
        decide_rename_hide_path(&sb.fs, old, new, 0, &stale).unwrap(),
        RenameDecision::Retry
    ));

    // A denied endpoint (the path pattern `sub/.env` matches `sub/.env`)
    // -> hide_path, decided from the fresh source identity.
    let denied_name = TestSandbox::cstr(".env");
    let denied = RenameEndpoint {
        fd: &sub_fd,
        dir: sub_inode,
        name: denied_name.as_c_str(),
    };
    let current = platform::fstat(keep_fd.raw()).unwrap();
    assert!(matches!(
        decide_rename_hide_path(&sb.fs, denied, new, 0, &current).unwrap(),
        RenameDecision::Deny
    ));

    // A denied destination is also a hide_path.
    assert!(matches!(
        decide_rename_hide_path(&sb.fs, old, denied, 0, &current).unwrap(),
        RenameDecision::Deny
    ));

    // Exchange-destination Retry predicate: a present destination that changed
    // identity, or disappeared, no longer matches; an unchanged one does, and an
    // initially-absent destination is stale once anything appears.
    let expected = ExchangeDest::capture(Some((10, 20)));
    assert!(expected.still_matches(Some((10, 20))));
    assert!(!expected.still_matches(Some((10, 21))));
    assert!(!expected.still_matches(None));

    let absent = ExchangeDest::capture(None);
    assert!(absent.still_matches(None));
    assert!(!absent.still_matches(Some((10, 20))));
}

//--------------------------------------------------------------------------------------------------
// Tests: hard link uses the source entry's real type
//--------------------------------------------------------------------------------------------------

/// A dir-only rule must be decided from the hard link source's real type: linking
/// a directory onto a dir-only-denied name is refused with EACCES before the
/// host `linkat` (which would otherwise surface EPERM), while a file source is
/// allowed because `node_modules/` does not match files.
#[test]
fn do_link_denies_dir_only_rule_using_source_type() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_dir("src_dir");
    let (_entry, _handle) = sb.fuse_create_root("src_file").unwrap();

    let src_dir = sb.lookup_root("src_dir").unwrap();
    let src_file = sb.lookup_root("src_file").unwrap();

    // Directory source onto the dir-only-denied name -> EACCES (not EPERM).
    TestSandbox::assert_errno(
        sb.fs.link(
            sb.ctx(),
            src_dir.inode,
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
        ),
        LINUX_EACCES,
    );

    // File source onto the same name is allowed: `node_modules/` matches only
    // directories.
    sb.fs
        .link(
            sb.ctx(),
            src_file.inode,
            ROOT_INODE,
            &TestSandbox::cstr("node_modules"),
        )
        .unwrap();
    sb.lookup_root("node_modules").unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests: name-based semantics
//--------------------------------------------------------------------------------------------------

// The ancestor-rename laundering gap is closed at configuration time: a path
// pattern (`sub/.env`) is rejected on a writable mount (see the SDK/runtime
// validators), so it can only be configured on a read-only mount, where the
// guest cannot rename. Only name-based gaps remain below.

/// A symlink whose target is denied does not expose the target.
///
/// The link entry itself is served (hide_path matches the entry name, and `link` is
/// allowed), but following the link resolves the target name, which is a fresh
/// lookup that hide_path rejects with `ENOENT`. The target's contents stay
/// unreachable; only the link entry's existence is observable, which is the
/// same name-based limitation as any allowed name.
#[test]
fn test_hide_path_symlink_to_denied_target_does_not_expose_target() {
    use std::os::unix::fs::symlink;
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        hide_path: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"secret");
    symlink(".env", sb.root.join("link")).unwrap();

    // The link entry is served: its own name `link` is not denied.
    let link = sb.lookup_root("link").unwrap();

    // Traverse the link: read its target, then resolve that target name.
    let target = sb.fs.readlink(sb.ctx(), link.inode).unwrap();
    assert_eq!(target, b".env", "the link points at the denied target");

    // Following the link is a fresh lookup of the target name, which hide_path
    // rejects, so the target's contents stay unreachable.
    TestSandbox::assert_errno(sb.lookup_root(".env"), LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: restored directory snapshots re-apply the destination hide-path list
//--------------------------------------------------------------------------------------------------

/// A name visible when a directory listing was captured must not reappear through
/// the restored snapshot once the destination hide-path list hides it.
///
/// Restore re-interning a saved directory snapshot bypasses live lookup and
/// readdir filtering, so the hide-path list must be re-applied while rebuilding the
/// snapshot. The denied file is never looked up, so it has no restored inode:
/// only the directory-snapshot re-filter can hide it.
#[test]
fn restored_directory_snapshot_drops_names_hidden_by_destination_hide_path() {
    use super::super::mobility::{capture, restore};

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    std::fs::write(tmp.path().join("sub/.env"), b"secret").unwrap();
    std::fs::write(tmp.path().join("sub/visible"), b"ok").unwrap();

    let source = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        ..Default::default()
    })
    .unwrap();
    source.init(FsOptions::empty()).unwrap();

    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 0,
    };
    let sub = source.lookup(ctx, ROOT_INODE, c"sub").unwrap().inode;
    let (handle, _) = source.opendir(ctx, sub, 0).unwrap();
    let handle = handle.unwrap();
    let captured = source.readdir(ctx, sub, handle, 4096, 0).unwrap();
    assert!(
        captured.iter().any(|entry| entry.name == b".env"),
        "the denied name must be visible at capture time"
    );
    let encoded = capture(&source).unwrap();

    let destination = PassthroughFs::new(PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        hide_path: vec![".env".to_string()],
        ..Default::default()
    })
    .unwrap();
    destination.init(FsOptions::empty()).unwrap();
    restore(&destination, &encoded).unwrap();

    let restored = destination.readdir(ctx, sub, handle, 4096, 0).unwrap();
    let names: Vec<&[u8]> = restored.iter().map(|entry| &entry.name[..]).collect();

    assert!(
        !names.contains(&b".env".as_slice()),
        "a denied name must not be served from a restored snapshot: {names:?}"
    );
    assert!(
        names.contains(&b"visible".as_slice()),
        "allowed names must remain visible: {names:?}"
    );
}
