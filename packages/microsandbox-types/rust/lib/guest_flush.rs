//! Optional guest filesystem writeback policy, independent of required storage barriers.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Guest filesystem writeback requested before capture or resident pause.
///
/// This policy controls root and captured block-filesystem writeback, including owned disks.
/// It never disables host-backed directory synchronization, host I/O draining, or snapshot
/// durability. Filesystem writeback does not flush application-owned buffers or commit
/// application transactions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum GuestFlush {
    /// Require writeback for live disk-only capture; no extra writeback for full capture,
    /// branching, or pause. Stopped disk capture does not establish a guest flush.
    #[default]
    Auto,
    /// Require acknowledged writeback before proceeding. A paused source must already
    /// hold a matching flush boundary; a stopped source cannot satisfy this request.
    Required,
    /// Skip optional writeback, retaining all mandatory storage barriers.
    Skip,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GuestFlush {
    /// Whether this policy requires optional writeback for a live source.
    ///
    /// Callers must separately enforce mandatory storage barriers and distinguish stopped
    /// capture from live disk capture. This predicate is not evidence that flushing occurred.
    pub fn requires_writeback(self, disk_only: bool) -> bool {
        match self {
            Self::Auto => disk_only,
            Self::Required => true,
            Self::Skip => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::str::FromStr for GuestFlush {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            "skip" => Ok(Self::Skip),
            _ => Err("guest flush must be auto, required, or skip"),
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
    fn live_defaults_depend_on_capture_scope() {
        for (policy, disk, full_or_pause) in [
            (GuestFlush::Auto, true, false),
            (GuestFlush::Required, true, true),
            (GuestFlush::Skip, false, false),
        ] {
            assert_eq!(policy.requires_writeback(true), disk);
            assert_eq!(policy.requires_writeback(false), full_or_pause);
        }
    }

    #[test]
    fn wire_policy_is_explicit_and_closed() {
        assert_eq!(GuestFlush::default(), GuestFlush::Auto);
        for (policy, wire) in [
            (GuestFlush::Auto, "\"auto\""),
            (GuestFlush::Required, "\"required\""),
            (GuestFlush::Skip, "\"skip\""),
        ] {
            assert_eq!(serde_json::to_string(&policy).unwrap(), wire);
            assert_eq!(serde_json::from_str::<GuestFlush>(wire).unwrap(), policy);
        }
        for invalid in ["true", "false", "null", "\"always\"", "\"off\""] {
            assert!(serde_json::from_str::<GuestFlush>(invalid).is_err());
        }
    }
}
