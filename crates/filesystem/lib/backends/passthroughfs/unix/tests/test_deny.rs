//! Tests for the bind-mount deny-list enforcement.

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests: component-only pattern (basename) matching
//--------------------------------------------------------------------------------------------------

/// A denied basename is invisible via lookup.
#[test]
fn test_deny_basename_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
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

/// On a case-sensitive mount/filesystem (the default for the Linux test temp dir),
/// deny matching stays byte-exact: `.env` does not hide a differently-cased
/// `.ENV`, because the host would treat those as distinct files. Over-folding
/// here would wrongly hide legitimate distinct files.
#[test]
fn test_deny_case_variant_not_hidden_on_case_sensitive_mount() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".ENV", b"case variant");

    // On a case-sensitive root the differently-cased name is a distinct file
    // and is served. On a case-insensitive host the probe folds and this lookup
    // would be ENOENT; that branch is covered by the Windows test suite.
    let entry = sb.lookup_root(".ENV");
    assert!(
        entry.is_ok(),
        "case-sensitive host must not fold a denied basename over a distinct file"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: structural `.`/`..` entries are never denied
//--------------------------------------------------------------------------------------------------

/// A `.*` pattern must not strip the structural `.` and `..` entries from
/// readdir, otherwise path walks break.
#[test]
fn test_deny_star_pattern_keeps_dot_and_dotdot() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".*".to_string()],
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
        "readdir must still contain '.' under a '.*' deny pattern"
    );
    assert!(
        names.contains(&b"..".as_slice()),
        "readdir must still contain '..' under a '.*' deny pattern"
    );
    assert!(
        !names.contains(&b".env".as_slice()),
        ".env should be hidden by the '.*' deny pattern"
    );
}

/// `lookup(".")` must resolve to the parent directory, not be denied by a
/// `.*` or `*` pattern.
#[test]
fn test_deny_star_pattern_lookup_dot_succeeds() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".*".to_string()],
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
fn test_deny_create_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".secrets".to_string()],
        ..cfg
    });

    TestSandbox::assert_errno(sb.fuse_create_root(".secrets"), LINUX_EACCES);

    // Normal create still works.
    let (entry, _handle) = sb.fuse_create_root("normal.txt").unwrap();
    assert_ne!(entry.inode, 0);
}

/// Creating a hidden directory returns EACCES from the deny list.
#[test]
fn test_deny_mkdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".hidden_dir".to_string(), "no_create.txt".to_string()],
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
fn test_deny_rename_from_denied_source() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".forbidden".to_string()],
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
fn test_deny_rename_to_denied_target() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".forbidden".to_string()],
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

/// Denied entries are omitted from readdir.
#[test]
fn test_deny_readdir_omits_entries() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string(), "*.log".to_string()],
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

//--------------------------------------------------------------------------------------------------
// Tests: unlink/rmdir EACCES
//--------------------------------------------------------------------------------------------------

/// Unlink of a denied name returns EACCES.
#[test]
fn test_deny_unlink_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".do-not-delete".to_string()],
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
fn test_deny_rmdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".protected-dir".to_string()],
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
fn test_deny_normal_ops_unchanged() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
        ..cfg
    });

    // Create, write, read all work on non-denied names.
    let (entry, handle) = sb.fuse_create_root("writeable.txt").unwrap();
    let written = sb
        .fuse_write(entry.inode, handle, b"hello deny", 0)
        .unwrap();
    assert_eq!(written, 10);

    let (handle, _) = sb
        .fs
        .open(sb.ctx(), entry.inode, false, LINUX_O_RDWR)
        .unwrap();
    let data = sb.fuse_read(entry.inode, handle.unwrap(), 10, 0).unwrap();
    assert_eq!(data, b"hello deny");

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
fn test_deny_path_pattern_lookup() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
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
fn test_deny_recursive_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["**/env.secret".to_string()],
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

/// Path patterns also gate create within a hidden subtree.
#[test]
fn test_deny_path_pattern_create() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".sub/.secret".to_string()],
        ..cfg
    });
    sb.host_create_dir(".sub");
    let dir = sb.lookup_root(".sub").unwrap();

    TestSandbox::assert_errno(sb.fuse_create(dir.inode, ".secret", 0o644), LINUX_EACCES);

    // Sibling create is unaffected.
    sb.fuse_create(dir.inode, "normal.txt", 0o644).unwrap();
}

/// A path pattern fires on a rename whose destination is the denied path.
///
/// This pins the location-based semantics of path patterns: `sub/.env` hides a
/// file *at* `sub/.env`, so renaming a visible file onto that path is rejected
/// with `EACCES`. (The converse — renaming a denied file *off* the path makes
/// it served — is pinned separately as the known ancestor-rename laundering
/// limitation.)
#[test]
fn test_deny_path_pattern_rename_onto_denied_path_is_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.fuse_create_root("src").unwrap();

    // The destination `sub/.env` matches the denied path, so the rename is
    // rejected before any host move happens.
    let sub = sb.lookup_root("sub").unwrap();
    TestSandbox::assert_errno(
        sb.fs.rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("src"),
            sub.inode,
            &TestSandbox::cstr(".env"),
            0,
        ),
        LINUX_EACCES,
    );

    // The source is untouched and the denied destination is still absent.
    sb.lookup_root("src").unwrap();
    TestSandbox::assert_errno(sb.lookup(sub.inode, ".env"), LINUX_ENOENT);
}

//--------------------------------------------------------------------------------------------------
// Tests: dir-only patterns (trailing `/`, e.g. `node_modules/`)
//--------------------------------------------------------------------------------------------------

/// A dir-only pattern hides a directory on lookup.
#[test]
fn test_deny_dir_only_lookup_hides_directory() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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
fn test_deny_dir_only_lookup_serves_same_named_file() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_file("node_modules", b"not a dir");

    // A file named node_modules is served (gitignore 'foo/' does not match files).
    let entry = sb.lookup_root("node_modules").unwrap();
    assert_ne!(entry.inode, 0);
}

/// A dir-only pattern allows creating a same-named file but rejects mkdir.
#[test]
fn test_deny_dir_only_mkdir_rejected_but_file_create_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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

/// A dir-only pattern omits the directory from readdir but keeps a same-named file.
#[test]
fn test_deny_dir_only_readdir_keeps_same_named_file() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
        ..cfg
    });
    sb.host_create_dir("node_modules");
    sb.host_create_dir("visible_dir");
    sb.host_create_file("visible.txt", b"ok");

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
}

/// A dir-only pattern rejects renaming a directory to the denied name but
/// allows renaming a same-named file there.
#[test]
fn test_deny_dir_only_rename_dir_rejected_file_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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
fn test_deny_dir_only_rename_file_over_hidden_dir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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
fn test_deny_dir_only_rename_exchange_dir_onto_denied_name_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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
fn test_deny_dir_only_rename_exchange_two_files_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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

/// Renaming a directory onto an already-hidden file returns EACCES.
///
/// A basename pattern such as `.env` matches both files and directories, so
/// this is caught by the source-type check (`source_is_dir = true`) rather
/// than leaking the hidden file's existence through a raw ENOTDIR.
#[test]
fn test_deny_rename_dir_over_hidden_file_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
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
fn test_deny_dir_only_rmdir_rejected() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
        ..cfg
    });

    sb.host_create_dir("node_modules");
    TestSandbox::assert_errno(
        sb.fs
            .rmdir(sb.ctx(), ROOT_INODE, &TestSandbox::cstr("node_modules")),
        LINUX_EACCES,
    );
}

/// A dir-only pattern allows unlink of a same-named file (gitignore 'foo/'
/// does not match files).
#[test]
fn test_deny_dir_only_unlink_same_named_file_allowed() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["node_modules/".to_string()],
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
fn test_deny_path_pattern_fails_closed_on_unresolvable_parent() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
        ..cfg
    });

    // A bogus parent inode is absent from the inode table, so its path cannot
    // be reconstructed. With active path patterns this must deny, never allow.
    assert!(
        sb.fs.deny_matches_name(1_000_000, b"secret", false),
        "unresolvable parent under path patterns must fail closed"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: known limitations pinned as #[ignore] (behavior documented, not yet enforced)
//--------------------------------------------------------------------------------------------------

/// Pins the H1 ancestor-rename laundering gap: renaming an ancestor directory
/// moves a denied path-pattern match to a non-denied name.
///
/// `deny: ["sub/.env"]` is location-based. Renaming `sub` -> `x` succeeds
/// (neither `sub` nor `x` matches the pattern), and the subsequent lookup of
/// `x/.env` reconstructs the path from the new anchor, so the file is served.
/// This is the documented confidentiality limitation of path patterns on a
/// writable mount (see docs/sandboxes/volumes.mdx); it is intentionally
/// `#[ignore]`d because the bypass is current behavior, not a bug to fail on.
#[test]
#[ignore = "known limitation: path patterns are location-based and laundered by ancestor rename"]
fn test_deny_ancestor_rename_launders_path_pattern() {
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec!["sub/.env".to_string()],
        ..cfg
    });
    sb.host_create_dir("sub");
    sb.host_create_file("sub/.env", b"secret");

    // The denied path is hidden before the rename.
    let sub = sb.lookup_root("sub").unwrap();
    TestSandbox::assert_errno(sb.lookup(sub.inode, ".env"), LINUX_ENOENT);

    // Renaming the ancestor launders the pattern: neither 'sub' nor 'x'
    // matches 'sub/.env', so the rename is allowed and the file is served
    // under the new anchor.
    sb.fs
        .rename(
            sb.ctx(),
            ROOT_INODE,
            &TestSandbox::cstr("sub"),
            ROOT_INODE,
            &TestSandbox::cstr("x"),
            0,
        )
        .unwrap();
    let x = sb.lookup_root("x").unwrap();
    let entry = sb.lookup(x.inode, ".env");
    assert!(
        !entry.is_ok(),
        "known limitation: laundered .env is currently served"
    );
}

/// Pins the symlink-target gap: deny matching checks the entry name, not the
/// resolved symlink target.
///
/// A symlink named `link` pointing at a denied relative path (`.env`) is
/// served, because the deny list sees `link` and never re-checks the target.
/// This is inherent to name-based deny lists and is documented in
/// docs/sandboxes/volumes.mdx; it is `#[ignore]`d because the bypass is
/// current behavior.
#[test]
#[ignore = "known limitation: deny matches the entry name, not the symlink target"]
fn test_deny_symlink_to_denied_target_is_served() {
    use std::os::unix::fs::symlink;
    let sb = TestSandbox::with_config(|cfg| PassthroughConfig {
        deny: vec![".env".to_string()],
        ..cfg
    });
    sb.host_create_file(".env", b"secret");
    symlink(".env", sb.root.join("link")).unwrap();

    // The symlink's own name 'link' does not match '.env', so it is served.
    let entry = sb.lookup_root("link");
    assert!(
        !entry.is_ok(),
        "known limitation: symlink to a denied target is served"
    );
}
