//! TTL-indexed reverse map from keys to members, with fast member-to-keys
//! lookup.
//!
//! Each key owns a set of members, and each member of a key carries its own
//! expiry. A reverse index (member -> keys) answers "which keys currently
//! contain this member?" in amortized O(1). Expiration uses a min-heap of
//! versioned events so a stale timer cannot remove a newer binding of the
//! same key and member.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Stale expiry events tolerated beyond twice the live bindings before the
/// heap is compacted.
const EXPIRATION_COMPACTION_SLACK: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TTL-indexed reverse map from keys to members and members back to keys.
#[derive(Debug)]
pub struct TtlReverseIndex<K, M> {
    by_key: HashMap<K, HashMap<M, Binding>>,
    by_member: HashMap<M, HashSet<K>>,
    expirations: BinaryHeap<Reverse<ExpiryEvent<K, M>>>,
    live_bindings: usize,
    member_limit: Option<usize>,
    next_version: u64,
    next_sequence: u64,
}

#[derive(Debug, Clone, Copy)]
struct Binding {
    expires_at: Instant,
    version: u64,
}

#[derive(Debug, Clone)]
struct ExpiryEvent<K, M> {
    expires_at: Instant,
    sequence: u64,
    version: u64,
    key: K,
    member: M,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<K, M> TtlReverseIndex<K, M>
where
    K: Eq + Hash + Clone,
    M: Eq + Hash + Clone,
{
    /// Create an index that keeps at most `limit` members per key.
    ///
    /// Binding new members to a key that is already full drops the members
    /// of that key closest to expiry. Members bound by the same call are
    /// never dropped for each other, so a call with more than `limit`
    /// members keeps them all. A `limit` of zero is treated as one.
    pub fn with_member_limit(limit: usize) -> Self {
        Self {
            member_limit: Some(limit.max(1)),
            ..Self::default()
        }
    }

    /// Insert or replace the member set for `key` with a new TTL.
    pub fn insert<I>(&mut self, key: K, members: I, ttl: Duration, now: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        self.evict_expired(now);
        self.remove_key(&key);
        self.bind_all(key, members, now + ttl);
    }

    /// Add `members` to the set for `key`, keeping the members already there.
    ///
    /// Each member stays bound until its own expiry. A member that is already
    /// bound keeps the later of its current expiry and `now + ttl`, so a
    /// shorter TTL never cuts an earlier binding short. An empty `members`
    /// changes nothing. With a member limit, a full key drops its members
    /// closest to expiry to make room, never one of `members`.
    pub fn extend<I>(&mut self, key: K, members: I, ttl: Duration, now: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        self.evict_expired(now);
        self.bind_all(key, members, now + ttl);
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
                    .and_then(|bindings| bindings.get(member))
                    .is_some_and(|binding| binding.expires_at > now && predicate(key))
            })
        })
    }

    /// Evict all bindings whose TTL has expired by `now`.
    pub fn evict_expired(&mut self, now: Instant) {
        while let Some(Reverse(expiry)) = self.expirations.peek() {
            if expiry.expires_at > now {
                break;
            }
            let expiry = self.expirations.pop().unwrap().0;
            if is_current(&self.by_key, &expiry) {
                self.unbind(&expiry.key, &expiry.member);
            }
        }
    }

    fn bind_all<I>(&mut self, key: K, members: I, expires_at: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        let members: HashSet<M> = members.into_iter().collect();
        for member in &members {
            self.bind(&key, member.clone(), expires_at);
        }
        self.trim_to_limit(&key, &members);
    }

    fn bind(&mut self, key: &K, member: M, expires_at: Instant) {
        let current = self
            .by_key
            .get(key)
            .and_then(|bindings| bindings.get(&member))
            .map(|binding| binding.expires_at);
        if current.is_some_and(|current| current >= expires_at) {
            return;
        }

        let version = self.next_version;
        self.next_version = self.next_version.wrapping_add(1);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);

        let replaced = self.by_key.entry(key.clone()).or_default().insert(
            member.clone(),
            Binding {
                expires_at,
                version,
            },
        );
        if replaced.is_none() {
            self.live_bindings += 1;
        }
        self.by_member
            .entry(member.clone())
            .or_default()
            .insert(key.clone());
        self.expirations.push(Reverse(ExpiryEvent {
            expires_at,
            sequence,
            version,
            key: key.clone(),
            member,
        }));
        self.compact_expirations();
    }

    /// Drop the members of `key` closest to expiry until it is back within
    /// the member limit, sparing the members in `kept`.
    fn trim_to_limit(&mut self, key: &K, kept: &HashSet<M>) {
        let Some(limit) = self.member_limit else {
            return;
        };
        let Some(bindings) = self.by_key.get(key) else {
            return;
        };
        let excess = bindings.len().saturating_sub(limit);
        if excess == 0 {
            return;
        }
        let mut droppable: Vec<(Instant, M)> = bindings
            .iter()
            .filter(|(member, _)| !kept.contains(*member))
            .map(|(member, binding)| (binding.expires_at, member.clone()))
            .collect();
        droppable.sort_by_key(|(expires_at, _)| *expires_at);
        for (_, member) in droppable.into_iter().take(excess) {
            self.unbind(key, &member);
        }
    }

    /// Drop expiry events whose binding was refreshed or removed once they
    /// outnumber the live bindings, so the heap stays proportional to them.
    fn compact_expirations(&mut self) {
        if self.expirations.len() <= 2 * self.live_bindings + EXPIRATION_COMPACTION_SLACK {
            return;
        }
        let by_key = &self.by_key;
        self.expirations
            .retain(|Reverse(expiry)| is_current(by_key, expiry));
    }

    fn remove_key(&mut self, key: &K) {
        let Some(removed) = self.by_key.remove(key) else {
            return;
        };

        self.live_bindings -= removed.len();
        for member in removed.into_keys() {
            self.forget_reverse(&member, key);
        }
    }

    fn unbind(&mut self, key: &K, member: &M) {
        let Some(bindings) = self.by_key.get_mut(key) else {
            return;
        };
        if bindings.remove(member).is_some() {
            self.live_bindings -= 1;
        }
        if bindings.is_empty() {
            self.by_key.remove(key);
        }
        self.forget_reverse(member, key);
    }

    fn forget_reverse(&mut self, member: &M, key: &K) {
        if let Some(keys) = self.by_member.get_mut(member) {
            keys.remove(key);
            if keys.is_empty() {
                self.by_member.remove(member);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<K, M> Default for TtlReverseIndex<K, M> {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
            by_member: HashMap::new(),
            expirations: BinaryHeap::new(),
            live_bindings: 0,
            member_limit: None,
            next_version: 0,
            next_sequence: 0,
        }
    }
}

impl<K, M> PartialEq for ExpiryEvent<K, M> {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at && self.sequence == other.sequence
    }
}

impl<K, M> Eq for ExpiryEvent<K, M> {}

impl<K, M> PartialOrd for ExpiryEvent<K, M> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K, M> Ord for ExpiryEvent<K, M> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.sequence.cmp(&other.sequence))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether `expiry` still belongs to the live binding of its key and member.
fn is_current<K, M>(by_key: &HashMap<K, HashMap<M, Binding>>, expiry: &ExpiryEvent<K, M>) -> bool
where
    K: Eq + Hash,
    M: Eq + Hash,
{
    by_key
        .get(&expiry.key)
        .and_then(|bindings| bindings.get(&expiry.member))
        .is_some_and(|binding| {
            binding.version == expiry.version && binding.expires_at == expiry.expires_at
        })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

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

    #[test]
    fn extend_keeps_members_from_earlier_calls() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(30), now);
        index.extend("alpha", [2], Duration::from_secs(30), now);

        assert!(index.member_matches(&1, now, |key| key == &"alpha"));
        assert!(index.member_matches(&2, now, |key| key == &"alpha"));
    }

    #[test]
    fn extend_expires_each_member_on_its_own_ttl() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(5), now);
        index.extend(
            "alpha",
            [2],
            Duration::from_secs(5),
            now + Duration::from_secs(3),
        );

        let between = now + Duration::from_secs(6);
        assert!(!index.member_matches(&1, between, |key| key == &"alpha"));
        assert!(index.member_matches(&2, between, |key| key == &"alpha"));

        // Evicting the first member must leave the second one bound.
        index.evict_expired(between);
        assert!(index.member_matches(&2, between, |key| key == &"alpha"));

        let after = now + Duration::from_secs(9);
        index.evict_expired(after);
        assert!(!index.member_matches(&2, after, |_| true));
        assert!(index.by_key.is_empty());
        assert!(index.by_member.is_empty());
    }

    #[test]
    fn extend_keeps_the_later_expiry_of_a_rebound_member() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(10), now);
        // A shorter TTL does not cut the earlier binding short.
        index.extend("alpha", [1], Duration::from_secs(2), now);
        assert!(index.member_matches(&1, now + Duration::from_secs(5), |key| key == &"alpha"));

        // A longer one extends it, and the first timer no longer removes it.
        index.extend("alpha", [1], Duration::from_secs(20), now);
        index.evict_expired(now + Duration::from_secs(11));
        assert!(index.member_matches(&1, now + Duration::from_secs(15), |key| key == &"alpha"));
        assert!(!index.member_matches(&1, now + Duration::from_secs(21), |key| key == &"alpha"));
    }

    #[test]
    fn extend_with_no_members_keeps_existing_ones() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(30), now);
        index.extend("alpha", std::iter::empty(), Duration::from_secs(30), now);

        assert!(index.member_matches(&1, now, |key| key == &"alpha"));
    }

    #[test]
    fn insert_and_remove_drop_every_extended_member() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(30), now);
        index.extend("alpha", [2], Duration::from_secs(30), now);
        index.insert("alpha", [3], Duration::from_secs(30), now);

        assert!(!index.member_matches(&1, now, |_| true));
        assert!(!index.member_matches(&2, now, |_| true));
        assert!(index.member_matches(&3, now, |key| key == &"alpha"));

        index.extend("alpha", [4], Duration::from_secs(30), now);
        index.remove(&"alpha", now);

        assert!(!index.member_matches(&3, now, |_| true));
        assert!(!index.member_matches(&4, now, |_| true));
        assert!(index.by_member.is_empty());
    }

    #[test]
    fn member_limit_drops_the_member_closest_to_expiry() {
        let mut index = TtlReverseIndex::<&str, i32>::with_member_limit(2);
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(10), now);
        index.extend("alpha", [2], Duration::from_secs(30), now);
        index.extend("alpha", [3], Duration::from_secs(20), now);

        assert!(!index.member_matches(&1, now, |_| true));
        assert!(index.member_matches(&2, now, |key| key == &"alpha"));
        assert!(index.member_matches(&3, now, |key| key == &"alpha"));

        // Refreshing a member already bound does not count against the limit.
        index.extend("alpha", [2], Duration::from_secs(40), now);
        assert!(index.member_matches(&3, now, |key| key == &"alpha"));
        assert_eq!(index.live_bindings, 2);
    }

    #[test]
    fn member_limit_keeps_every_member_of_one_call() {
        let mut index = TtlReverseIndex::<&str, i32>::with_member_limit(2);
        let now = Instant::now();

        index.extend("alpha", [1], Duration::from_secs(60), now);
        index.extend("alpha", [2, 3, 4], Duration::from_secs(10), now);

        // The answer's own members all stay, and the older member makes room.
        assert!(!index.member_matches(&1, now, |_| true));
        for i in 2..=4 {
            assert!(index.member_matches(&i, now, |key| key == &"alpha"));
        }

        // The next answer trims the key back to the limit.
        index.extend("alpha", [5], Duration::from_secs(30), now);
        assert_eq!(index.by_key["alpha"].len(), 2);
        assert!(index.member_matches(&5, now, |key| key == &"alpha"));
        assert_eq!(index.live_bindings, 2);

        let mut index = TtlReverseIndex::<&str, i32>::with_member_limit(2);
        index.insert("alpha", [1, 2, 3], Duration::from_secs(10), now);
        assert_eq!(index.by_key["alpha"].len(), 3);
    }

    #[test]
    fn member_limit_bounds_a_rotating_answer() {
        let mut index = TtlReverseIndex::<&str, i32>::with_member_limit(8);
        let now = Instant::now();

        for i in 0..1_000 {
            index.extend("alpha", [i], Duration::from_secs(86_400), now);
        }

        assert_eq!(index.by_key["alpha"].len(), 8);
        assert_eq!(index.by_member.len(), 8);
        assert!(index.member_matches(&999, now, |key| key == &"alpha"));
    }

    #[test]
    fn refreshes_and_removals_keep_the_expiry_heap_bounded() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        // Each refresh with a longer TTL leaves the previous event stale.
        for i in 1..=1_000 {
            index.extend("alpha", [1], Duration::from_secs(i), now);
        }
        assert!(index.expirations.len() <= 2 * index.live_bindings + EXPIRATION_COMPACTION_SLACK);
        assert!(index.member_matches(&1, now + Duration::from_secs(999), |key| key == &"alpha"));

        // Cleared keys leave their events behind until the next compaction.
        for i in 0..1_000 {
            index.insert("beta", [i], Duration::from_secs(86_400), now);
            index.remove(&"beta", now);
        }
        assert!(index.expirations.len() <= 2 * index.live_bindings + EXPIRATION_COMPACTION_SLACK);
        assert_eq!(index.live_bindings, 1);
    }
}
