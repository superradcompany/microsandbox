// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Borrow;
use std::collections::BTreeMap;

/// A BTreeMap that supports 2 types of keys per value. All the usual restrictions and warnings for
/// `std::collections::BTreeMap` also apply to this struct. Additionally, there is a 1:1
/// relationship between the 2 key types. In other words, for each `K1` in the map, there is exactly
/// one `K2` in the map and vice versa.
#[derive(Default)]
pub struct MultikeyBTreeMap<K1, K2, V>
where
    K1: Ord,
    K2: Ord,
{
    // We need to keep a copy of the second key in the main map so that we can remove entries using
    // just the main key. Otherwise we would require the caller to provide both keys when calling
    // `remove`.
    main: BTreeMap<K1, (K2, V)>,
    alt: BTreeMap<K2, K1>,
}

impl<K1, K2, V> MultikeyBTreeMap<K1, K2, V>
where
    K1: Clone + Ord,
    K2: Clone + Ord,
{
    /// Create a new empty MultikeyBTreeMap.
    pub fn new() -> Self {
        MultikeyBTreeMap {
            main: BTreeMap::default(),
            alt: BTreeMap::default(),
        }
    }

    /// Returns a reference to the value corresponding to the key.
    ///
    /// The key may be any borrowed form of `K1``, but the ordering on the borrowed form must match
    /// the ordering on `K1`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K1: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.main.get(key).map(|(_, v)| v)
    }

    /// Returns a reference to the value corresponding to the alternate key.
    ///
    /// The key may be any borrowed form of the `K2``, but the ordering on the borrowed form must
    /// match the ordering on `K2`.
    ///
    /// Note that this method performs 2 lookups: one to get the main key and another to get the
    /// value associated with that key. For best performance callers should prefer the `get` method
    /// over this method whenever possible as `get` only needs to perform one lookup.
    pub fn get_alt<Q2>(&self, key: &Q2) -> Option<&V>
    where
        K2: Borrow<Q2>,
        Q2: Ord + ?Sized,
    {
        if let Some(k) = self.alt.get(key) {
            self.get(k)
        } else {
            None
        }
    }

    /// Inserts a new entry into the map with the given keys and value.
    ///
    /// Returns `None` if the map did not have an entry with `k1` or `k2` present. If exactly one
    /// key was present, then the value associated with that key is updated, the other key is
    /// removed, and the old value is returned. If **both** keys were present then the value
    /// associated with the main key is updated, the value associated with the alternate key is
    /// removed, and the old value associated with the main key is returned.
    pub fn insert(&mut self, k1: K1, k2: K2, v: V) -> Option<V> {
        let oldval = if let Some(oldkey) = self.alt.insert(k2.clone(), k1.clone()) {
            self.main.remove(&oldkey)
        } else {
            None
        };
        self.main
            .insert(k1, (k2.clone(), v))
            .or(oldval)
            .map(|(oldk2, v)| {
                if oldk2 != k2 {
                    self.alt.remove(&oldk2);
                }
                v
            })
    }

    /// Remove a key from the map, returning the value associated with that key if it was previously
    /// in the map.
    ///
    /// The key may be any borrowed form of `K1``, but the ordering on the borrowed form must match
    /// the ordering on `K1`.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K1: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.main.remove(key).map(|(k2, v)| {
            self.alt.remove(&k2);
            v
        })
    }

    /// Clears the map, removing all values.
    pub fn clear(&mut self) {
        self.alt.clear();
        self.main.clear()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        assert_eq!(*m.get(&k1).expect("failed to look up main key"), val);
        assert_eq!(*m.get_alt(&k2).expect("failed to look up alt key"), val);
    }

    #[test]
    fn update_main_key() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        let new_k1 = 0x3add_f8f8_c7c5_df5e;
        let val2 = 0x7389_f8a7;
        assert_eq!(
            m.insert(new_k1, k2, val2)
                .expect("failed to update main key"),
            val
        );

        assert!(m.get(&k1).is_none());
        assert_eq!(*m.get(&new_k1).expect("failed to look up main key"), val2);
        assert_eq!(*m.get_alt(&k2).expect("failed to look up alt key"), val2);
    }

    #[test]
    fn update_alt_key() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        let new_k2 = 0x6825_a60b_61ac_b333;
        let val2 = 0xbb14_8f2c;
        assert_eq!(
            m.insert(k1, new_k2, val2)
                .expect("failed to update alt key"),
            val
        );

        assert!(m.get_alt(&k2).is_none());
        assert_eq!(*m.get(&k1).expect("failed to look up main key"), val2);
        assert_eq!(
            *m.get_alt(&new_k2).expect("failed to look up alt key"),
            val2
        );
    }

    #[test]
    fn update_value() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        let val2 = 0xe42d_79ba;
        assert_eq!(
            m.insert(k1, k2, val2).expect("failed to update alt key"),
            val
        );

        assert_eq!(*m.get(&k1).expect("failed to look up main key"), val2);
        assert_eq!(*m.get_alt(&k2).expect("failed to look up alt key"), val2);
    }

    #[test]
    fn update_both_keys_main() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        let new_k1 = 0xc980_587a_24b3_ae30;
        let new_k2 = 0x2773_c5ee_8239_45a2;
        let val2 = 0x31f4_33f9;
        assert!(m.insert(new_k1, new_k2, val2).is_none());

        let val3 = 0x8da1_9cf7;
        assert_eq!(
            m.insert(k1, new_k2, val3)
                .expect("failed to update main key"),
            val
        );

        // Both new_k1 and k2 should now be gone from the map.
        assert!(m.get(&new_k1).is_none());
        assert!(m.get_alt(&k2).is_none());

        assert_eq!(*m.get(&k1).expect("failed to look up main key"), val3);
        assert_eq!(
            *m.get_alt(&new_k2).expect("failed to look up alt key"),
            val3
        );
    }

    #[test]
    fn update_both_keys_alt() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        let new_k1 = 0xc980_587a_24b3_ae30;
        let new_k2 = 0x2773_c5ee_8239_45a2;
        let val2 = 0x31f4_33f9;
        assert!(m.insert(new_k1, new_k2, val2).is_none());

        let val3 = 0x8da1_9cf7;
        assert_eq!(
            m.insert(new_k1, k2, val3)
                .expect("failed to update main key"),
            val2
        );

        // Both k1 and new_k2 should now be gone from the map.
        assert!(m.get(&k1).is_none());
        assert!(m.get_alt(&new_k2).is_none());

        assert_eq!(*m.get(&new_k1).expect("failed to look up main key"), val3);
        assert_eq!(*m.get_alt(&k2).expect("failed to look up alt key"), val3);
    }

    #[test]
    fn remove() {
        let mut m = MultikeyBTreeMap::<u64, i64, u32>::new();

        let k1 = 0xc6c8_f5e0_b13e_ed40;
        let k2 = 0x1a04_ce4b_8329_14fe;
        let val = 0xf4e3_c360;
        assert!(m.insert(k1, k2, val).is_none());

        assert_eq!(m.remove(&k1).expect("failed to remove entry"), val);
        assert!(m.get(&k1).is_none());
        assert!(m.get_alt(&k2).is_none());
    }
}
