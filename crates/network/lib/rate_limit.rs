//! Token-bucket rate limiting for the virtio-net boundary.
//!
//! [`RateLimiter`] enforces a [`RateLimiterConfig`] on one traffic
//! direction: an optional bandwidth bucket charged per frame byte and an
//! optional ops bucket charged one token per frame. Callers supply the
//! current [`Instant`] so refill math stays deterministic under test.
//!
//! Buckets start full plus their one-time burst and refill continuously at
//! `size` tokens per `refill_time_ms`. A frame larger than the bandwidth
//! bucket is permitted once and then blocks the limiter proportionally, so
//! oversized frames throttle instead of sticking forever.

use std::time::{Duration, Instant};

use microsandbox_types::{RateLimitConfigError, RateLimiterConfig, TokenBucketConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Rate limiter for one traffic direction (TX or RX).
#[derive(Debug)]
pub struct RateLimiter {
    bandwidth: Option<TokenBucket>,
    ops: Option<TokenBucket>,
    /// Set after an over-consumption charge: the limiter refuses every
    /// frame until this instant so the overage is repaid.
    blocked_until: Option<Instant>,
}

/// A single token bucket with continuous refill and a one-time burst.
#[derive(Debug)]
struct TokenBucket {
    /// Bucket capacity in tokens.
    size: u64,
    /// Time to refill `size` tokens, in nanoseconds.
    refill_time_ns: u128,
    /// Startup-only tokens, spent before the balance and never refilled.
    one_time_burst: u64,
    /// Current token balance, capped at `size`.
    balance: u64,
    /// Refill progress marker. Advanced only by whole granted tokens so the
    /// fractional remainder carries into the next refill.
    last_refill: Instant,
}

/// Outcome of planning a charge against one bucket, before committing it.
enum BucketCharge {
    /// The charge fits the current balance (including burst).
    Ready,
    /// The charge exceeds the bucket capacity; it may proceed once as an
    /// over-consumption that blocks the limiter for the returned duration.
    Overdraft(Duration),
    /// Not enough tokens yet; retry after the returned duration.
    Blocked(Duration),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RateLimiter {
    /// Create a limiter from a validated config. `now` seeds the refill
    /// clocks so both buckets start full plus their one-time burst.
    pub fn new(config: &RateLimiterConfig, now: Instant) -> Result<Self, RateLimitConfigError> {
        config.validate()?;
        Ok(Self {
            bandwidth: config.bandwidth.as_ref().map(|b| TokenBucket::new(b, now)),
            ops: config.ops.as_ref().map(|b| TokenBucket::new(b, now)),
            blocked_until: None,
        })
    }

    /// Charge one frame of `frame_len` bytes against both buckets.
    ///
    /// The charge is atomic: if either bucket blocks, neither is charged and
    /// the returned instant is the earliest time both charges can succeed.
    pub fn try_consume_frame(&mut self, frame_len: u64, now: Instant) -> Result<(), Instant> {
        if let Some(until) = self.blocked_until {
            if now < until {
                return Err(until);
            }
            self.blocked_until = None;
        }

        // Refills are always safe to commit; only the charge is atomic.
        if let Some(bucket) = &mut self.bandwidth {
            bucket.refill(now);
        }
        if let Some(bucket) = &mut self.ops {
            bucket.refill(now);
        }

        let charges = [
            self.bandwidth.as_ref().map(|b| b.plan(frame_len)),
            self.ops.as_ref().map(|b| b.plan(1)),
        ];
        let blocked_for = charges
            .iter()
            .flatten()
            .filter_map(|charge| match charge {
                BucketCharge::Blocked(wait) => Some(*wait),
                _ => None,
            })
            .max();
        if let Some(wait) = blocked_for {
            return Err(now + wait);
        }

        let overdraft = charges
            .iter()
            .flatten()
            .filter_map(|charge| match charge {
                BucketCharge::Overdraft(wait) => Some(*wait),
                _ => None,
            })
            .max();
        if let Some(bucket) = &mut self.bandwidth {
            bucket.commit(frame_len);
        }
        if let Some(bucket) = &mut self.ops {
            bucket.commit(1);
        }
        if let Some(wait) = overdraft {
            self.blocked_until = Some(now + wait);
        }
        Ok(())
    }
}

impl TokenBucket {
    /// Create a bucket that starts full plus its one-time burst.
    fn new(config: &TokenBucketConfig, now: Instant) -> Self {
        Self {
            size: config.size,
            refill_time_ns: config.refill_time_ms as u128 * 1_000_000,
            one_time_burst: config.one_time_burst,
            balance: config.size,
            last_refill: now,
        }
    }

    /// Grant tokens earned since the last refill, keeping the sub-token
    /// remainder pending by advancing `last_refill` only by whole tokens.
    fn refill(&mut self, now: Instant) {
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        let tokens = elapsed_ns * self.size as u128 / self.refill_time_ns;
        if tokens == 0 {
            return;
        }

        self.balance = self
            .balance
            .saturating_add(u64::try_from(tokens).unwrap_or(u64::MAX))
            .min(self.size);
        let granted_ns = tokens * self.refill_time_ns / self.size as u128;
        self.last_refill += Duration::from_nanos(u64::try_from(granted_ns).unwrap_or(u64::MAX));
    }

    /// Plan a charge without committing it.
    fn plan(&self, tokens: u64) -> BucketCharge {
        let after_burst = tokens.saturating_sub(self.one_time_burst);
        if after_burst <= self.balance {
            return BucketCharge::Ready;
        }
        if after_burst > self.size {
            return BucketCharge::Overdraft(self.refill_duration(after_burst));
        }
        BucketCharge::Blocked(self.refill_duration(after_burst - self.balance))
    }

    /// Commit a planned charge: burst tokens spend first, and an
    /// over-consumption empties the balance (the limiter-level block repays
    /// the overage).
    fn commit(&mut self, tokens: u64) {
        let burst_spend = tokens.min(self.one_time_burst);
        self.one_time_burst -= burst_spend;
        self.balance = self.balance.saturating_sub(tokens - burst_spend);
    }

    /// Time to refill `tokens`, rounded up so the deadline is never early.
    fn refill_duration(&self, tokens: u64) -> Duration {
        let ns = (tokens as u128 * self.refill_time_ns).div_ceil(self.size as u128);
        Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(size: u64, refill_time_ms: u64, one_time_burst: u64) -> TokenBucketConfig {
        TokenBucketConfig {
            size,
            refill_time_ms,
            one_time_burst,
        }
    }

    fn bandwidth_limiter(size: u64, refill_time_ms: u64, burst: u64) -> RateLimiter {
        RateLimiter::new(
            &RateLimiterConfig {
                bandwidth: Some(bucket(size, refill_time_ms, burst)),
                ops: None,
            },
            base(),
        )
        .unwrap()
    }

    fn base() -> Instant {
        // A fixed anchor: tests advance time by adding durations to it.
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *BASE.get_or_init(Instant::now)
    }

    #[test]
    fn bucket_starts_full() {
        let mut limiter = bandwidth_limiter(1000, 1000, 0);
        assert!(limiter.try_consume_frame(1000, base()).is_ok());
    }

    #[test]
    fn empty_bucket_blocks_with_refill_deadline() {
        let mut limiter = bandwidth_limiter(1000, 1000, 0);
        assert!(limiter.try_consume_frame(1000, base()).is_ok());

        // 600 tokens short: the deadline lands 600ms out.
        let deadline = limiter.try_consume_frame(600, base()).unwrap_err();
        assert_eq!(deadline - base(), Duration::from_millis(600));

        // Retrying at the deadline succeeds.
        assert!(limiter.try_consume_frame(600, deadline).is_ok());
    }

    #[test]
    fn refill_is_continuous_not_stepwise() {
        let mut limiter = bandwidth_limiter(1000, 1000, 0);
        assert!(limiter.try_consume_frame(1000, base()).is_ok());

        // Half the refill interval earns half the bucket.
        let halfway = base() + Duration::from_millis(500);
        assert!(limiter.try_consume_frame(500, halfway).is_ok());
        assert!(limiter.try_consume_frame(1, halfway).is_err());
    }

    #[test]
    fn fractional_refill_carries_into_the_next_grant() {
        // 3 tokens per second: one token every 333.3ms.
        let mut limiter = bandwidth_limiter(3, 1000, 0);
        assert!(limiter.try_consume_frame(3, base()).is_ok());

        // 333ms earns 0 whole tokens (0.999).
        let early = base() + Duration::from_millis(333);
        assert!(limiter.try_consume_frame(1, early).is_err());

        // The 0.999 fraction is not discarded by the failed attempt: 334ms
        // total crosses one whole token.
        let after = base() + Duration::from_millis(334);
        assert!(limiter.try_consume_frame(1, after).is_ok());

        // The fraction beyond the granted token carries: the second token
        // completes at 667ms, not 334ms + 333ms rounded away.
        let second = base() + Duration::from_millis(667);
        assert!(limiter.try_consume_frame(1, second).is_ok());
    }

    #[test]
    fn one_time_burst_spends_first_and_never_refills() {
        let mut limiter = bandwidth_limiter(10, 1000, 5);

        // 15 = 5 burst + 10 balance drains everything up front.
        assert!(limiter.try_consume_frame(15, base()).is_ok());

        // A full refill later the bucket holds only `size`: the burst is gone.
        let later = base() + Duration::from_secs(60);
        assert!(limiter.try_consume_frame(10, later).is_ok());
        assert!(limiter.try_consume_frame(1, later).is_err());
    }

    #[test]
    fn oversized_frame_passes_once_then_blocks_proportionally() {
        let mut limiter = bandwidth_limiter(1000, 1000, 0);

        // 2500 bytes can never fit a 1000-byte bucket; permit it once.
        assert!(limiter.try_consume_frame(2500, base()).is_ok());

        // The limiter then blocks for the frame's full cost: 2.5 refills.
        let deadline = limiter.try_consume_frame(1, base()).unwrap_err();
        assert_eq!(deadline - base(), Duration::from_millis(2500));

        // Once repaid, traffic flows again.
        assert!(limiter.try_consume_frame(1000, deadline).is_ok());
    }

    #[test]
    fn ops_bucket_charges_one_token_per_frame() {
        let mut limiter = RateLimiter::new(
            &RateLimiterConfig {
                bandwidth: None,
                ops: Some(bucket(2, 1000, 0)),
            },
            base(),
        )
        .unwrap();

        assert!(limiter.try_consume_frame(100_000, base()).is_ok());
        assert!(limiter.try_consume_frame(1, base()).is_ok());
        let deadline = limiter.try_consume_frame(1, base()).unwrap_err();
        assert_eq!(deadline - base(), Duration::from_millis(500));
    }

    #[test]
    fn blocked_ops_bucket_leaves_bandwidth_uncharged() {
        // Bandwidth refills slowly (100 tokens/s) so a stray charge is
        // visible; ops refills one token per second.
        let mut limiter = RateLimiter::new(
            &RateLimiterConfig {
                bandwidth: Some(bucket(1000, 10_000, 0)),
                ops: Some(bucket(1, 1000, 0)),
            },
            base(),
        )
        .unwrap();

        assert!(limiter.try_consume_frame(400, base()).is_ok());
        // Ops exhausted: the 400-byte charge must not touch the bandwidth
        // bucket.
        assert!(limiter.try_consume_frame(400, base()).is_err());

        // One second later: 600 remaining + 100 refilled bandwidth tokens.
        // Had the failed attempt charged bandwidth, only 300 would be left.
        let later = base() + Duration::from_secs(1);
        assert!(limiter.try_consume_frame(700, later).is_ok());
    }

    #[test]
    fn blocked_deadline_covers_both_buckets() {
        let mut limiter = RateLimiter::new(
            &RateLimiterConfig {
                bandwidth: Some(bucket(1000, 1000, 0)),
                ops: Some(bucket(1, 2000, 0)),
            },
            base(),
        )
        .unwrap();

        assert!(limiter.try_consume_frame(1000, base()).is_ok());

        // Bandwidth is ready after 1s but the op takes 2s; the retry
        // deadline must wait for the slower bucket.
        let deadline = limiter.try_consume_frame(1000, base()).unwrap_err();
        assert_eq!(deadline - base(), Duration::from_secs(2));
        assert!(limiter.try_consume_frame(1000, deadline).is_ok());
    }

    #[test]
    fn rejects_invalid_configs() {
        let empty = RateLimiterConfig {
            bandwidth: None,
            ops: None,
        };
        assert_eq!(
            RateLimiter::new(&empty, base()).unwrap_err(),
            RateLimitConfigError::EmptyLimiter
        );

        let zero_size = RateLimiterConfig {
            bandwidth: Some(bucket(0, 1000, 0)),
            ops: None,
        };
        assert_eq!(
            RateLimiter::new(&zero_size, base()).unwrap_err(),
            RateLimitConfigError::ZeroSize {
                bucket: "bandwidth"
            }
        );

        let zero_refill = RateLimiterConfig {
            bandwidth: None,
            ops: Some(bucket(10, 0, 0)),
        };
        assert_eq!(
            RateLimiter::new(&zero_refill, base()).unwrap_err(),
            RateLimitConfigError::ZeroRefillTime { bucket: "ops" }
        );
    }
}
