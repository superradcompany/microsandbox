//! One connection string for every database backend.
//!
//! A database target is a bare filesystem path or `sqlite://` URL for the
//! local SQLite file, or a `libsql://` URL for a self-hosted libSQL server
//! (`sqld`). The connection openers accept either form through the same
//! entry points and dispatch on the scheme.

use std::{
    fmt,
    path::{Path, PathBuf},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SQLITE_SCHEME: &str = "sqlite://";
const LIBSQL_SCHEME: &str = "libsql://";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Where the database lives: a local SQLite file or a self-hosted libSQL
/// server.
///
/// Built infallibly from paths and strings so existing path-based callers
/// keep working; an unrecognized scheme is rejected with a clear error when
/// the target is opened, not while it is carried around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbTarget {
    kind: TargetKind,
}

/// Parsed backend selection for a [`DbTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// Local SQLite file.
    File(PathBuf),
    /// Remote server endpoint, normalized to the `http(s)://` URL the
    /// libsql client connects to.
    Remote(String),
    /// A `scheme://` string this crate does not recognize.
    Unsupported(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DbTarget {
    /// Whether this target names a remote database server rather than a
    /// local file. Unrecognized schemes count as remote-shaped: they are
    /// URLs, and the open path reports them with their own error.
    pub fn is_remote(&self) -> bool {
        !matches!(self.kind, TargetKind::File(_))
    }

    pub(crate) fn kind(&self) -> &TargetKind {
        &self.kind
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&str> for DbTarget {
    fn from(target: &str) -> Self {
        // Self-hosted sqld speaks plain hrana-over-HTTP; on loopback there
        // is no TLS to negotiate, so `libsql://host:port` normalizes to
        // `http://host:port`. Explicit `http(s)://` passes through for
        // callers that want to be literal about the transport.
        let kind = if let Some(rest) = target.strip_prefix(SQLITE_SCHEME) {
            TargetKind::File(PathBuf::from(rest))
        } else if let Some(rest) = target.strip_prefix(LIBSQL_SCHEME) {
            TargetKind::Remote(format!("http://{rest}"))
        } else if target.starts_with("http://") || target.starts_with("https://") {
            TargetKind::Remote(target.to_owned())
        } else if target.contains("://") {
            TargetKind::Unsupported(target.to_owned())
        } else {
            TargetKind::File(PathBuf::from(target))
        };
        Self { kind }
    }
}

impl From<String> for DbTarget {
    fn from(target: String) -> Self {
        Self::from(target.as_str())
    }
}

impl From<&String> for DbTarget {
    fn from(target: &String) -> Self {
        Self::from(target.as_str())
    }
}

impl From<&Path> for DbTarget {
    fn from(path: &Path) -> Self {
        Self {
            kind: TargetKind::File(path.to_path_buf()),
        }
    }
}

impl From<&PathBuf> for DbTarget {
    fn from(path: &PathBuf) -> Self {
        Self::from(path.as_path())
    }
}

impl From<PathBuf> for DbTarget {
    fn from(path: PathBuf) -> Self {
        Self {
            kind: TargetKind::File(path),
        }
    }
}

impl fmt::Display for DbTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            TargetKind::File(path) => write!(f, "{}", path.display()),
            TargetKind::Remote(url) => write!(f, "{url}"),
            TargetKind::Unsupported(raw) => write!(f, "{raw}"),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_path_is_a_file_target() {
        let target = DbTarget::from("/abs/path/msb.db");
        assert_eq!(
            target.kind(),
            &TargetKind::File(PathBuf::from("/abs/path/msb.db"))
        );
        assert!(!target.is_remote());
    }

    #[test]
    fn sqlite_scheme_is_a_file_target() {
        let target = DbTarget::from("sqlite:///abs/path/msb.db");
        assert_eq!(
            target.kind(),
            &TargetKind::File(PathBuf::from("/abs/path/msb.db"))
        );
    }

    #[test]
    fn libsql_scheme_normalizes_to_http() {
        let target = DbTarget::from("libsql://127.0.0.1:8890");
        assert_eq!(
            target.kind(),
            &TargetKind::Remote("http://127.0.0.1:8890".to_owned())
        );
        assert!(target.is_remote());
    }

    #[test]
    fn http_urls_pass_through() {
        let target = DbTarget::from("https://db.example:8890");
        assert_eq!(
            target.kind(),
            &TargetKind::Remote("https://db.example:8890".to_owned())
        );
    }

    #[test]
    fn unknown_scheme_is_unsupported() {
        let target = DbTarget::from("postgres://127.0.0.1:5432/db");
        assert!(matches!(target.kind(), TargetKind::Unsupported(_)));
    }

    #[test]
    fn paths_never_parse_as_urls() {
        let path = PathBuf::from("libsql:%2F%2Fodd dir/msb.db");
        let target = DbTarget::from(&path);
        assert_eq!(target.kind(), &TargetKind::File(path));
    }
}
