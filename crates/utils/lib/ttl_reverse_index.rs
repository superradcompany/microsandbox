//! TTL-indexed reverse map from keys to members, with fast member-to-keys
//! lookup.
//!
//! Each key owns members with individual expiries. A reverse index maps
//! members back to their keys. An ordered map holds exactly one expiry entry
//! per binding; refreshing or removing a binding removes its old entry.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// TTL-indexed reverse map from keys to members and members back to keys.
#[derive(Debug)]
pub struct TtlReverseIndex<K, M> {
    by_key: HashMap<K, HashMap<M, Expiry>>,
    by_member: HashMap<M, HashSet<K>>,
    expirations: BTreeMap<Expiry, (K, M)>,
    next_sequence: u64,
}

/// The sequence distinguishes bindings with the same expiry without requiring
/// keys or members to implement `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Expiry {
    expires_at: Instant,
    sequence: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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
        self.remove_key(&key);
        self.bind_all(key, members, now + ttl);
    }

    /// Add `members` to the set for `key`, keeping the members already there.
    ///
    /// Each member stays bound until its own expiry. A member that is already
    /// bound keeps the later of its current expiry and `now + ttl`, so a
    /// shorter TTL never cuts an earlier binding short. An empty `members`
    /// changes nothing.
    pub fn extend<I>(&mut self, key: K, members: I, ttl: Duration, now: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        self.evict_expired(now);
        self.bind_all(key, members, now + ttl);
    }

    /// Extend only if all new bindings fit within `capacity` after expiry cleanup.
    ///
    /// Returns `false` without changing any live bindings when the answer does
    /// not fit. Duplicate members count once; existing bindings can refresh at
    /// capacity. Temporary storage is also bounded by `capacity`.
    pub fn try_extend<I>(
        &mut self,
        key: K,
        members: I,
        ttl: Duration,
        now: Instant,
        capacity: usize,
    ) -> bool
    where
        I: IntoIterator<Item = M>,
    {
        self.evict_expired(now);

        let remaining = capacity.saturating_sub(self.expirations.len());
        let existing = self.by_key.get(&key);
        let mut unique = HashSet::new();
        let mut added = 0;

        for member in members {
            if unique.contains(&member) {
                continue;
            }
            if !existing.is_some_and(|bindings| bindings.contains_key(&member)) {
                added += 1;
                if added > remaining {
                    return false;
                }
            }
            unique.insert(member);
        }

        self.bind_all(key, unique, now + ttl);
        true
    }

    /// Number of stored bindings across all keys. Call [`Self::evict_expired`]
    /// first when only live bindings should count toward a capacity limit.
    pub fn binding_count(&self) -> usize {
        self.expirations.len()
    }

    /// Number of stored members for `key`, including entries not yet evicted.
    pub fn member_count(&self, key: &K) -> usize {
        self.by_key.get(key).map_or(0, HashMap::len)
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
                    .is_some_and(|expiry| expiry.expires_at > now && predicate(key))
            })
        })
    }

    /// Evict all bindings whose TTL has expired by `now`.
    pub fn evict_expired(&mut self, now: Instant) {
        while self
            .expirations
            .first_key_value()
            .is_some_and(|(expiry, _)| expiry.expires_at <= now)
        {
            if let Some((_, (key, member))) = self.expirations.pop_first() {
                self.unbind(&key, &member);
            }
        }
    }

    fn bind_all<I>(&mut self, key: K, members: I, expires_at: Instant)
    where
        I: IntoIterator<Item = M>,
    {
        for member in members {
            self.bind(&key, member, expires_at);
        }
    }

    fn bind(&mut self, key: &K, member: M, expires_at: Instant) {
        let bindings = self.by_key.entry(key.clone()).or_default();
        if let Some(previous) = bindings.get(&member) {
            if previous.expires_at >= expires_at {
                return;
            }
            self.expirations.remove(previous);
        }

        let expiry = Expiry {
            expires_at,
            sequence: self.next_sequence,
        };
        self.next_sequence = self.next_sequence.wrapping_add(1);

        bindings.insert(member.clone(), expiry);
        self.by_member
            .entry(member.clone())
            .or_default()
            .insert(key.clone());
        self.expirations.insert(expiry, (key.clone(), member));
    }

    fn remove_key(&mut self, key: &K) {
        let Some(removed) = self.by_key.remove(key) else {
            return;
        };

        for (member, expiry) in removed {
            self.expirations.remove(&expiry);
            self.forget_reverse(&member, key);
        }
    }

    /// Remove a binding whose expiry entry has already been popped.
    fn unbind(&mut self, key: &K, member: &M) {
        let Some(bindings) = self.by_key.get_mut(key) else {
            return;
        };

        bindings.remove(member);
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
            expirations: BTreeMap::new(),
            next_sequence: 0,
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
        // members are visible afterward and expiry maintenance preserves
        // the live entry.
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

        // Maintenance before the final entry expires must leave it live.
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
    fn expiry_metadata_stays_bounded_during_refresh_and_remove_churn() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();

        for i in 0..10_000 {
            index.extend("alpha", [1], Duration::from_secs(60 + i), now);
        }
        assert_eq!(
            index.expirations.len(),
            1,
            "refreshes retained stale timers"
        );
        assert!(index.member_matches(&1, now + Duration::from_secs(10_000), |_| true));

        for i in 0..10_000 {
            index.extend("beta", [i], Duration::from_secs(60), now);
            index.remove(&"beta", now);
        }
        assert_eq!(index.expirations.len(), 1, "removals retained stale timers");
        index.evict_expired(now + Duration::from_secs(10_060));
        assert!(index.expirations.is_empty());
        assert!(!index.member_matches(&1, now + Duration::from_secs(10_060), |_| true));

        // Clearing a large live set must release its timers immediately,
        // without relying on a later insertion to trigger maintenance.
        index.extend("bulk", 0..20_000, Duration::from_secs(86_400), now);
        index.remove(&"bulk", now);
        assert!(index.expirations.is_empty());
    }

    #[test]
    fn bounded_extend_is_atomic_and_reclaims_expired_capacity() {
        let mut index = TtlReverseIndex::<&str, i32>::default();
        let now = Instant::now();
        let short = Duration::from_secs(10);
        let long = Duration::from_secs(60);

        assert!(index.try_extend("alpha", [1, 1], short, now, 3));
        // Sharing an address across keys still consumes another binding.
        assert!(index.try_extend("beta", [1], long, now, 3));
        // One free slot cannot admit two new members. Neither the new members
        // nor a longer deadline for an existing member may be partially applied.
        assert!(!index.try_extend("alpha", [1, 2, 3], long, now, 3));
        assert!(!index.member_matches(&2, now, |_| true));
        assert!(!index.member_matches(&3, now, |_| true));
        assert!(!index.member_matches(&1, now + short, |key| *key == "alpha"));
        assert!(index.try_extend("gamma", [4], short, now, 3));
        assert!(!index.try_extend("delta", [5], long, now, 3));
        assert!(index.try_extend("beta", [1, 1], long, now + Duration::from_secs(1), 3));
        assert!(index.member_matches(&1, now + long, |key| *key == "beta"));

        // Exact expiry frees two slots, while the refreshed binding survives.
        assert!(index.try_extend("delta", [5, 6], long, now + short, 3));
        assert!(index.member_matches(&1, now + short, |key| *key == "beta"));
        assert!(index.member_matches(&5, now + short, |key| *key == "delta"));
        assert!(index.member_matches(&6, now + short, |key| *key == "delta"));
        assert!(!index.try_extend("epsilon", [7], long, now + short, 3));
        index.remove(&"delta", now + short);
        assert!(index.try_extend("epsilon", [7, 8], long, now + short, 3));
    }

    #[test]
    fn mixed_operations_match_a_flat_reference_model() {
        // The reference has no reverse index or expiry queue: it answers each
        // lookup by scanning a flat list of observations and their deadlines.
        for seed in [1_u64, 42, 0xdead_beef] {
            let mut random = seed;
            let mut next = || {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                random >> 32
            };
            let mut index = TtlReverseIndex::<u8, u8>::default();
            let mut observations: Vec<(u8, u8, Instant)> = Vec::new();
            let mut now = Instant::now();

            for step in 0..4_096 {
                let key = (next() % 8) as u8;
                let count = (next() % 5) as usize;
                let members: Vec<u8> = (0..count).map(|_| (next() % 8) as u8).collect();
                let ttl = Duration::from_secs([0, 1, 2, 8, 64][(next() % 5) as usize]);
                let operation = next() % 6;
                observations.retain(|&(_, _, expiry)| expiry > now);

                match operation {
                    0..=2 => {
                        if operation == 0 {
                            index.insert(key, members.iter().copied(), ttl, now);
                            observations.retain(|&(owner, _, _)| owner != key);
                        } else {
                            index.extend(key, members.iter().copied(), ttl, now);
                        }
                        for member in members {
                            // Preserve every observation independently. A binding
                            // is live if any observation of that pair is live.
                            observations.push((key, member, now + ttl));
                        }
                    }
                    3 => {
                        index.remove(&key, now);
                        observations.retain(|&(owner, _, _)| owner != key);
                    }
                    4 => now += Duration::from_secs(next() % 4),
                    _ => index.evict_expired(now),
                }

                // Reads must reject expired bindings even before maintenance.
                for at in [now, now + Duration::from_secs(1)] {
                    for member in 0..8 {
                        for owner in 0..8 {
                            let expected = observations
                                .iter()
                                .any(|&(k, m, expiry)| k == owner && m == member && expiry > at);
                            assert_eq!(
                                index.member_matches(&member, at, |k| *k == owner),
                                expected,
                                "seed {seed}, step {step}, key {owner}, member {member}"
                            );
                        }
                    }
                }

                index.evict_expired(now);
                let live: HashSet<_> = observations
                    .iter()
                    .filter(|(_, _, expiry)| *expiry > now)
                    .map(|&(key, member, _)| (key, member))
                    .collect();
                assert_eq!(
                    index.expirations.len(),
                    live.len(),
                    "expiry storage grew beyond live bindings at seed {seed}, step {step}"
                );
            }

            index.evict_expired(now + Duration::from_secs(65));
            assert!(index.expirations.is_empty());
            assert!(index.by_key.is_empty());
            assert!(index.by_member.is_empty());
        }
    }
}
