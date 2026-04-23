//! TTL-indexed reverse map from keys to members, with fast member-to-keys
//! lookup.
//!
//! Each key owns a set of members and a single TTL. A reverse index
//! (member -> keys) answers "which keys currently contain this member?" in
//! amortized O(1). Expiration uses a min-heap of versioned events so a
//! stale timer cannot remove a newer replacement of the same key.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// TTL-indexed reverse map from keys to members and members back to keys.
#[derive(Debug)]
pub struct TtlReverseIndex<K, M> {
    by_key: HashMap<K, IndexedEntry<M>>,
    by_member: HashMap<M, HashSet<K>>,
    expirations: BinaryHeap<Reverse<ExpiryEvent<K>>>,
    next_version: u64,
    next_sequence: u64,
}

#[derive(Debug)]
struct IndexedEntry<M> {
    members: HashSet<M>,
    expires_at: Instant,
    version: u64,
}

#[derive(Debug, Clone)]
struct ExpiryEvent<K> {
    expires_at: Instant,
    sequence: u64,
    version: u64,
    key: K,
}

impl<K, M> Default for TtlReverseIndex<K, M> {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
            by_member: HashMap::new(),
            expirations: BinaryHeap::new(),
            next_version: 0,
            next_sequence: 0,
        }
    }
}

impl<K, M> TtlReverseIndex<K, M>
where
    K: Eq + Hash + Clone,
    M: Eq + Hash + Clone,
{
    /// Insert or replace the member set for `key` with a new TTL.
    pub fn insert<I>(&mut self, key: K, members: I, ttl: Duration, now: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        self.evict_expired(now);

        let members: HashSet<M> = members.into_iter().collect();
        if members.is_empty() {
            self.remove(&key, now);
            return;
        }

        self.remove_key(&key);

        let expires_at = now + ttl;
        let version = self.next_version;
        self.next_version = self.next_version.wrapping_add(1);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);

        for member in &members {
            self.by_member
                .entry(member.clone())
                .or_default()
                .insert(key.clone());
        }

        self.by_key.insert(
            key.clone(),
            IndexedEntry {
                members,
                expires_at,
                version,
            },
        );
        self.expirations.push(Reverse(ExpiryEvent {
            expires_at,
            sequence,
            version,
            key,
        }));
    }

    /// Remove the entry for `key` if present.
    pub fn remove(&mut self, key: &K, now: Instant) {
        self.evict_expired(now);
        self.remove_key(key);
    }

    /// Returns true if `member` is associated with any non-expired key that
    /// satisfies `predicate`.
    pub fn member_matches(
        &self,
        member: &M,
        now: Instant,
        mut predicate: impl FnMut(&K) -> bool,
    ) -> bool {
        self.by_member.get(member).is_some_and(|keys| {
            keys.iter().any(|key| {
                self.by_key
                    .get(key)
                    .is_some_and(|entry| entry.expires_at > now && predicate(key))
            })
        })
    }

    /// Evict all entries whose TTL has expired by `now`.
    pub fn evict_expired(&mut self, now: Instant) {
        while let Some(Reverse(expiry)) = self.expirations.peek() {
            if expiry.expires_at > now {
                break;
            }
            let expiry = self.expirations.pop().unwrap().0;
            let should_remove = self.by_key.get(&expiry.key).is_some_and(|entry| {
                entry.version == expiry.version && entry.expires_at == expiry.expires_at
            });
            if should_remove {
                self.remove_key(&expiry.key);
            }
        }
    }

    fn remove_key(&mut self, key: &K) {
        let Some(removed) = self.by_key.remove(key) else {
            return;
        };

        for member in removed.members {
            if let Some(keys) = self.by_member.get_mut(&member) {
                keys.remove(key);
                if keys.is_empty() {
                    self.by_member.remove(&member);
                }
            }
        }
    }
}

impl<K> PartialEq for ExpiryEvent<K> {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.sequence == other.sequence
    }
}

impl<K> Eq for ExpiryEvent<K> {}

impl<K> PartialOrd for ExpiryEvent<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for ExpiryEvent<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_members_for_key() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1, 2], Duration::from_secs(30), now);
        index.insert("alpha", [3], Duration::from_secs(30), now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(index.member_matches(&3, now, |key| key == &"alpha"));
    }

    #[test]
    fn expires_entries() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);

        assert!(index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(!index.member_matches(&1, now + Duration::from_secs(6), |key| key == &"alpha"));

        index.evict_expired(now + Duration::from_secs(6));
        assert!(!index.member_matches(&1, now + Duration::from_secs(6), |key| key == &"alpha"));
    }

    #[test]
    fn stale_expiry_does_not_remove_newer_entry() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);
        index.insert(
            "alpha",
            [2],
            Duration::from_secs(10),
            now + Duration::from_secs(2),
        );

        index.evict_expired(now + Duration::from_secs(6));

        assert!(!index.member_matches(&1, now + Duration::from_secs(6), |key| key == &"alpha"));
        assert!(index.member_matches(&2, now + Duration::from_secs(6), |key| key == &"alpha"));
    }

    #[test]
    fn remove_clears_reverse_membership() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1, 2], Duration::from_secs(30), now);
        index.remove(&"alpha", now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(!index.member_matches(&2, now, |key| key == &"alpha"));
    }

    #[test]
    fn empty_insert_removes_existing_entry() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(30), now);
        index.insert("alpha", std::iter::empty(), Duration::from_secs(30), now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
    }

    #[test]
    fn overlapping_members_are_tracked_per_key() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1, 2], Duration::from_secs(30), now);
        index.insert("beta", [2, 3], Duration::from_secs(30), now);
        index.remove(&"alpha", now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(!index.member_matches(&2, now, |key| key == &"alpha"));
        assert!(index.member_matches(&2, now, |key| key == &"beta"));
        assert!(index.member_matches(&3, now, |key| key == &"beta"));
    }

    #[test]
    fn duplicate_members_are_deduplicated() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1, 1, 1], Duration::from_secs(30), now);
        index.remove(&"alpha", now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
    }

    #[test]
    fn write_side_eviction_cleans_expired_state() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);
        index.insert(
            "beta",
            [2],
            Duration::from_secs(5),
            now + Duration::from_secs(6),
        );

        assert!(!index.member_matches(&1, now + Duration::from_secs(6), |key| key == &"alpha"));
        assert!(index.member_matches(&2, now + Duration::from_secs(6), |key| key == &"beta"));
    }

    #[test]
    fn member_matches_returns_false_when_predicate_rejects_all_keys() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(30), now);
        index.insert("beta", [1], Duration::from_secs(30), now);

        assert!(!index.member_matches(&1, now, |_| false));
        assert!(index.member_matches(&1, now, |key| key == &"beta"));
    }

    #[test]
    fn member_matches_skips_expired_key_and_finds_live_sibling() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);
        index.insert("beta", [1], Duration::from_secs(60), now);

        let later = now + Duration::from_secs(10);
        assert!(!index.member_matches(&1, later, |key| key == &"alpha"));
        assert!(index.member_matches(&1, later, |key| key == &"beta"));
    }

    #[test]
    fn evict_expired_cleans_reverse_index_entry() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);
        index.evict_expired(now + Duration::from_secs(10));

        // No key currently contains member 1.
        assert!(!index.member_matches(&1, now + Duration::from_secs(10), |_| true));

        // Reinsert under a new key — the old reverse entry must be gone,
        // otherwise the predicate would be called with the stale key.
        index.insert(
            "beta",
            [1],
            Duration::from_secs(5),
            now + Duration::from_secs(10),
        );
        let mut seen_alpha = false;
        index.member_matches(&1, now + Duration::from_secs(10), |key| {
            if key == &"alpha" {
                seen_alpha = true;
            }
            false
        });
        assert!(!seen_alpha, "evicted key leaked through reverse index");
    }

    #[test]
    fn missing_member_returns_false() {
        let index = TtlReverseIndex::<&str, i32>::default();
        assert!(!index.member_matches(&42, Instant::now(), |_| true));
    }

    #[test]
    fn remove_nonexistent_key_is_noop() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();
        index.remove(&"never-inserted", now);
        index.remove(&"never-inserted", now);
        assert!(!index.member_matches(&1, now, |_| true));
    }

    #[test]
    fn zero_ttl_is_immediately_expired() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::ZERO, now);

        // `member_matches` uses strict `expires_at > now`, so TTL 0 is dead
        // on arrival.
        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
    }

    #[test]
    fn repeated_replaces_keep_reverse_index_consistent() {
        // Stress version of `stale_expiry_does_not_remove_newer_entry`:
        // churn the same key many times and confirm only the latest
        // members are visible afterward, and earlier heap events do not
        // wipe the live entry.
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        for i in 0..64 {
            index.insert("alpha", [i], Duration::from_secs(5), now);
        }
        // Final members: [63]. All earlier members must be absent from
        // the reverse index.
        for i in 0..63 {
            assert!(
                !index.member_matches(&i, now, |_| true),
                "stale member {i} leaked through reverse index"
            );
        }
        assert!(index.member_matches(&63, now, |key| key == &"alpha"));

        // Eviction past every scheduled expiry event for the churned key
        // must not remove the final live entry (version guard).
        index.evict_expired(now + Duration::from_secs(3));
        assert!(index.member_matches(&63, now + Duration::from_secs(3), |key| key == &"alpha"));
    }

    #[test]
    fn evict_is_idempotent() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1], Duration::from_secs(5), now);
        let later = now + Duration::from_secs(10);
        index.evict_expired(later);
        index.evict_expired(later);
        index.evict_expired(later);

        assert!(!index.member_matches(&1, later, |_| true));
    }

    #[test]
    fn burst_insert_then_partial_eviction_keeps_live_entries() {
        // Simulates a DNS burst: many hostnames resolve in quick
        // succession, some with short TTLs and some long. After time
        // advances past the short TTLs, only long-lived entries remain.
        let mut index = TtlReverseIndex::<String, i32>::default();
        let now = Instant::now();

        for i in 0..50 {
            let ttl = if i % 2 == 0 {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(60)
            };
            index.insert(format!("host-{i}"), [i], ttl, now);
        }

        let later = now + Duration::from_secs(10);
        index.evict_expired(later);

        for i in 0..50 {
            let host = format!("host-{i}");
            let hit = index.member_matches(&i, later, |key| key == &host);
            if i % 2 == 0 {
                assert!(!hit, "short-TTL host-{i} should have expired");
            } else {
                assert!(hit, "long-TTL host-{i} should still be live");
            }
        }
    }

    #[test]
    fn replace_preserves_reverse_for_sibling_keys_sharing_member() {
        // Keys alpha and beta both contain member 1. Replacing alpha's
        // members must not remove 1 from beta's reverse membership.
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.insert("alpha", [1, 2], Duration::from_secs(30), now);
        index.insert("beta", [1, 3], Duration::from_secs(30), now);

        index.insert("alpha", [4], Duration::from_secs(30), now);

        assert!(!index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(index.member_matches(&1, now, |key| key == &"beta"));
        assert!(index.member_matches(&3, now, |key| key == &"beta"));
        assert!(index.member_matches(&4, now, |key| key == &"alpha"));
    }
}
