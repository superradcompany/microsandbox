use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};

use super::*;

#[test]
fn test_new_valid_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    assert_eq!(fs.next_inode.load(Ordering::Relaxed), 3); // 1=root, 2=init
    assert_eq!(fs.next_handle.load(Ordering::Relaxed), 1); // 0=init handle
}

#[test]
fn test_new_nonexistent_dir() {
    let cfg = PassthroughConfig {
        root_dir: PathBuf::from("/nonexistent/path/that/does/not/exist"),
        ..Default::default()
    };
    let result = PassthroughFs::new(cfg);
    assert!(result.is_err());
}

#[test]
fn test_new_file_not_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("not_a_dir");
    std::fs::write(&file_path, b"hello").unwrap();
    let cfg = PassthroughConfig {
        root_dir: file_path,
        ..Default::default()
    };
    let result = PassthroughFs::new(cfg);
    assert!(result.is_err());
}

#[test]
fn test_init_registers_root() {
    let sb = TestSandbox::new();
    let (st, _timeout) = sb.fs.getattr(sb.ctx(), ROOT_INODE, None).unwrap();
    let mode = st.st_mode as u32;
    assert_ne!(mode & libc::S_IFMT as u32, 0);
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFDIR as u32);
}

#[test]
fn test_init_returns_requested_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    let opts = fs
        .init(FsOptions::DONT_MASK | FsOptions::BIG_WRITES)
        .unwrap();
    assert!(opts.contains(FsOptions::DONT_MASK));
    assert!(opts.contains(FsOptions::BIG_WRITES));
}

#[test]
fn test_init_writeback_default_off() {
    let sb = TestSandbox::new();
    assert!(!sb.fs.writeback.load(Ordering::Relaxed));
}

#[test]
fn test_destroy_clears_state() {
    let sb = TestSandbox::new();
    // Verify root is accessible before destroy.
    assert!(sb.fs.getattr(sb.ctx(), ROOT_INODE, None).is_ok());
    sb.fs.destroy();
    // After destroy, inode table is empty — getattr should fail.
    let result = sb.fs.getattr(sb.ctx(), ROOT_INODE, None);
    assert!(result.is_err());
}

#[test]
fn test_cache_open_never() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.cache_policy = CachePolicy::Never;
        cfg
    });
    assert_eq!(sb.fs.cache_open_options(), OpenOptions::DIRECT_IO);
}

#[test]
fn test_cache_open_auto() {
    let sb = TestSandbox::new(); // default is Auto
    assert_eq!(sb.fs.cache_open_options(), OpenOptions::empty());
}

#[test]
fn test_cache_open_always() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.cache_policy = CachePolicy::Always;
        cfg
    });
    assert_eq!(sb.fs.cache_open_options(), OpenOptions::KEEP_CACHE);
}

#[test]
fn test_cache_dir_always() {
    let sb = TestSandbox::with_config(|mut cfg| {
        cfg.cache_policy = CachePolicy::Always;
        cfg
    });
    assert_eq!(sb.fs.cache_dir_options(), OpenOptions::CACHE_DIR);
}

#[test]
fn test_default_config_values() {
    let cfg = PassthroughConfig::default();
    assert!(cfg.xattr);
    assert!(cfg.strict);
    assert_eq!(cfg.entry_timeout, Duration::from_secs(5));
    assert_eq!(cfg.attr_timeout, Duration::from_secs(5));
    assert_eq!(cfg.cache_policy, CachePolicy::Auto);
    assert!(!cfg.writeback);
}

#[test]
fn test_init_negotiates_killpriv_v2() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    let opts = fs.init(FsOptions::HANDLE_KILLPRIV_V2).unwrap();
    assert!(
        opts.contains(FsOptions::HANDLE_KILLPRIV_V2),
        "HANDLE_KILLPRIV_V2 should be negotiated when kernel offers it"
    );
}

#[test]
fn test_init_no_killpriv_when_not_offered() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = PassthroughConfig {
        root_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    let opts = fs.init(FsOptions::empty()).unwrap();
    assert!(
        !opts.contains(FsOptions::HANDLE_KILLPRIV_V2),
        "HANDLE_KILLPRIV_V2 should not be set when kernel does not offer it"
    );
}
