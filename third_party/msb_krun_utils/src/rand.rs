// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::time;

/// Generates pseudo random u32 numbers based on the current timestamp.
pub fn xor_rng_u32() -> u32 {
    let mut t: u32 = time::timestamp_cycles() as u32;
    // Taken from https://en.wikipedia.org/wiki/Xorshift.
    t ^= t << 13;
    t ^= t >> 17;
    t ^ (t << 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{Duration, Instant};

    #[test]
    fn test_xor_rng_u32() {
        let first = xor_rng_u32();
        let deadline = Instant::now() + Duration::from_millis(50);

        while Instant::now() < deadline {
            if xor_rng_u32() != first {
                return;
            }
            std::hint::spin_loop();
        }

        assert_ne!(first, xor_rng_u32());
    }
}
