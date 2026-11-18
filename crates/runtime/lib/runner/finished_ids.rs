//! Compact completion tracking for single-use IDs in one connection's range.

use std::ops::Range;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Remembers finished IDs without retaining an object for every completed operation.
pub(crate) struct FinishedIds {
    range: Range<u32>,
    // Each bit records one finished ID. Storage grows lazily and is bounded by the range.
    words: Vec<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FinishedIds {
    /// Track IDs in an owner-assigned range, excluding its end.
    pub(crate) fn new(range: Range<u32>) -> Self {
        Self {
            range,
            words: Vec::new(),
        }
    }

    /// Check completion without allocating; IDs outside the range are not tracked.
    pub(crate) fn is_finished(&self, id: u32) -> bool {
        let Some((word, mask)) = self.bit(id) else {
            return false;
        };
        self.words.get(word).is_some_and(|bits| bits & mask != 0)
    }

    /// Record completion, returning false if the ID is outside the assigned range.
    pub(crate) fn mark_finished(&mut self, id: u32) -> bool {
        let Some((word, mask)) = self.bit(id) else {
            return false;
        };
        if self.words.len() <= word {
            self.words.resize(word + 1, 0);
        }
        self.words[word] |= mask;
        true
    }

    fn bit(&self, id: u32) -> Option<(usize, u64)> {
        if !self.range.contains(&id) {
            return None;
        }

        let offset = usize::try_from(id.checked_sub(self.range.start)?).ok()?;
        Some((
            offset / u64::BITS as usize,
            1u64 << (offset % u64::BITS as usize),
        ))
    }
}
