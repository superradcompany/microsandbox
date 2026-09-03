// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

//! Token-bucket rate limiting for virtio-net devices.

use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

/// Configuration for one virtio-net traffic direction.
///
/// Bandwidth and operation limits are independent. When both are present, a
/// frame is admitted only when both buckets can pay their charge atomically.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RateLimiterConfig {
    /// Byte-based token bucket. One token pays for one Ethernet-frame byte.
    pub bandwidth: Option<TokenBucketConfig>,
    /// Operation-based token bucket. One token pays for one Ethernet frame.
    pub ops: Option<TokenBucketConfig>,
}

/// Optional rate limiters for both virtio-net directions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RateLimiters {
    /// Frames received by the guest from the backend.
    pub rx: Option<RateLimiterConfig>,
    /// Frames transmitted by the guest to the backend.
    pub tx: Option<RateLimiterConfig>,
}

/// Configuration for one continuously refilled token bucket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBucketConfig {
    /// Maximum recurring token balance and tokens granted per refill period.
    pub size: u64,
    /// Time in which `size` tokens are granted continuously.
    pub refill_time: Duration,
    /// Extra startup-only tokens, spent first and never refilled.
    pub one_time_burst: u64,
}

/// Invalid rate-limiter configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RateLimiterConfigError {
    /// Neither bandwidth nor operation limiting was configured.
    Empty,
    /// A configured bucket has zero capacity.
    ZeroSize(&'static str),
    /// A configured bucket has a zero refill period.
    ZeroRefillTime(&'static str),
}

/// Runtime limiter for one virtio-net traffic direction.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    bandwidth: Option<TokenBucket>,
    ops: Option<TokenBucket>,
    blocked_until: Option<Instant>,
}

#[derive(Debug)]
struct TokenBucket {
    size: u64,
    refill_time_ns: u128,
    one_time_burst: u64,
    balance: i128,
    last_refill: Instant,
}

enum BucketCharge {
    Ready,
    Overdraft(Instant),
    Blocked(Instant),
}

impl RateLimiterConfig {
    /// Validate this limiter and both configured token buckets.
    pub fn validate(&self) -> Result<(), RateLimiterConfigError> {
        if self.bandwidth.is_none() && self.ops.is_none() {
            return Err(RateLimiterConfigError::Empty);
        }
        if let Some(bucket) = &self.bandwidth {
            bucket.validate("bandwidth")?;
        }
        if let Some(bucket) = &self.ops {
            bucket.validate("ops")?;
        }
        Ok(())
    }
}

impl RateLimiters {
    /// Return true when neither direction is rate limited.
    pub fn is_empty(&self) -> bool {
        self.rx.is_none() && self.tx.is_none()
    }
}

impl TokenBucketConfig {
    fn validate(&self, name: &'static str) -> Result<(), RateLimiterConfigError> {
        if self.size == 0 {
            return Err(RateLimiterConfigError::ZeroSize(name));
        }
        if self.refill_time.is_zero() {
            return Err(RateLimiterConfigError::ZeroRefillTime(name));
        }
        Ok(())
    }
}

impl fmt::Display for RateLimiterConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("rate limiter must configure bandwidth, ops, or both"),
            Self::ZeroSize(bucket) => write!(f, "{bucket} bucket size must be greater than zero"),
            Self::ZeroRefillTime(bucket) => {
                write!(f, "{bucket} bucket refill time must be greater than zero")
            }
        }
    }
}

impl Error for RateLimiterConfigError {}

impl RateLimiter {
    pub(crate) fn new(
        config: &RateLimiterConfig,
        now: Instant,
    ) -> Result<Self, RateLimiterConfigError> {
        config.validate()?;
        Ok(Self {
            bandwidth: config
                .bandwidth
                .as_ref()
                .map(|bucket| TokenBucket::new(bucket, now)),
            ops: config
                .ops
                .as_ref()
                .map(|bucket| TokenBucket::new(bucket, now)),
            blocked_until: None,
        })
    }

    /// Atomically charge one Ethernet frame or return its retry deadline.
    pub(crate) fn try_consume_frame(
        &mut self,
        frame_len: u64,
        now: Instant,
    ) -> Result<(), Instant> {
        if let Some(deadline) = self.blocked_until {
            if now < deadline {
                return Err(deadline);
            }
            self.blocked_until = None;
        }

        if let Some(bucket) = &mut self.bandwidth {
            bucket.refill(now);
        }
        if let Some(bucket) = &mut self.ops {
            bucket.refill(now);
        }

        let charges = [
            self.bandwidth.as_ref().map(|bucket| bucket.plan(frame_len)),
            self.ops.as_ref().map(|bucket| bucket.plan(1)),
        ];
        if let Some(deadline) = charges
            .iter()
            .flatten()
            .filter_map(|charge| match charge {
                BucketCharge::Blocked(deadline) => Some(*deadline),
                _ => None,
            })
            .max()
        {
            return Err(deadline);
        }

        let overdraft_until = charges
            .iter()
            .flatten()
            .filter_map(|charge| match charge {
                BucketCharge::Overdraft(deadline) => Some(*deadline),
                _ => None,
            })
            .max();

        if let Some(bucket) = &mut self.bandwidth {
            bucket.commit(frame_len);
        }
        if let Some(bucket) = &mut self.ops {
            bucket.commit(1);
        }
        self.blocked_until = overdraft_until;
        Ok(())
    }
}

impl TokenBucket {
    fn new(config: &TokenBucketConfig, now: Instant) -> Self {
        Self {
            size: config.size,
            refill_time_ns: config.refill_time.as_nanos(),
            one_time_burst: config.one_time_burst,
            balance: config.size as i128,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if self.balance >= self.size as i128 {
            self.last_refill = now;
            return;
        }

        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos();
        let tokens = elapsed_ns.saturating_mul(self.size as u128) / self.refill_time_ns;
        if tokens == 0 {
            return;
        }

        self.balance = self
            .balance
            .saturating_add(i128::try_from(tokens).unwrap_or(i128::MAX));
        if self.balance >= self.size as i128 {
            self.balance = self.size as i128;
            self.last_refill = now;
            return;
        }

        let granted_ns = tokens.saturating_mul(self.refill_time_ns) / self.size as u128;
        self.last_refill += Duration::from_nanos(u64::try_from(granted_ns).unwrap_or(u64::MAX));
    }

    fn plan(&self, tokens: u64) -> BucketCharge {
        let balance_cost = tokens.saturating_sub(self.one_time_burst) as i128;
        if balance_cost <= self.balance {
            return BucketCharge::Ready;
        }

        let deadline = self.refill_deadline(balance_cost - self.balance);
        if balance_cost > self.size as i128 {
            BucketCharge::Overdraft(deadline)
        } else {
            BucketCharge::Blocked(deadline)
        }
    }

    fn commit(&mut self, tokens: u64) {
        let burst_spend = tokens.min(self.one_time_burst);
        self.one_time_burst -= burst_spend;
        self.balance -= (tokens - burst_spend) as i128;
    }

    fn refill_deadline(&self, tokens: i128) -> Instant {
        let ns = (tokens.max(0) as u128)
            .saturating_mul(self.refill_time_ns)
            .div_ceil(self.size as u128);
        self.last_refill + Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bandwidth: (u64, u64), ops: u64) -> RateLimiterConfig {
        RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: bandwidth.0,
                refill_time: Duration::from_secs(1),
                one_time_burst: bandwidth.1,
            }),
            ops: Some(TokenBucketConfig {
                size: ops,
                refill_time: Duration::from_secs(1),
                one_time_burst: 0,
            }),
        }
    }

    #[test]
    fn enforces_bandwidth_burst_and_ops_atomically() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(&config((1_000, 500), 2), start).unwrap();

        assert_eq!(limiter.try_consume_frame(1_200, start), Ok(()));
        assert_eq!(limiter.try_consume_frame(100, start), Ok(()));

        // Ops blocks this frame. Bandwidth must remain untouched while it waits.
        assert_eq!(
            limiter.try_consume_frame(200, start),
            Err(start + Duration::from_millis(500))
        );
        assert_eq!(limiter.bandwidth.as_ref().unwrap().balance, 200);
        assert_eq!(
            limiter.try_consume_frame(200, start + Duration::from_millis(499)),
            Err(start + Duration::from_millis(500))
        );
        assert_eq!(
            limiter.try_consume_frame(200, start + Duration::from_millis(500)),
            Ok(())
        );
    }

    #[test]
    fn oversized_frame_from_partial_balance_repays_exact_debt() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(&config((1_000, 0), 10), start).unwrap();

        assert_eq!(limiter.try_consume_frame(600, start), Ok(()));
        assert_eq!(limiter.try_consume_frame(2_500, start), Ok(()));
        assert_eq!(
            limiter.try_consume_frame(1, start + Duration::from_millis(2_099)),
            Err(start + Duration::from_millis(2_100))
        );
        assert_eq!(
            limiter.try_consume_frame(1_000, start + Duration::from_millis(2_100)),
            Err(start + Duration::from_millis(3_100))
        );
        assert_eq!(
            limiter.try_consume_frame(1_000, start + Duration::from_millis(3_100)),
            Ok(())
        );
    }

    #[test]
    fn fractional_refill_progress_carries_between_attempts() {
        let start = Instant::now();
        let config = RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: 3,
                refill_time: Duration::from_secs(1),
                one_time_burst: 0,
            }),
            ops: None,
        };
        let mut limiter = RateLimiter::new(&config, start).unwrap();

        assert_eq!(limiter.try_consume_frame(3, start), Ok(()));
        assert_eq!(
            limiter.try_consume_frame(1, start + Duration::from_millis(333)),
            Err(start + Duration::from_nanos(333_333_334))
        );
        assert_eq!(
            limiter.try_consume_frame(1, start + Duration::from_millis(334)),
            Ok(())
        );
        assert_eq!(
            limiter.try_consume_frame(1, start + Duration::from_millis(667)),
            Ok(())
        );
    }

    #[test]
    fn one_time_burst_is_spent_once_and_never_refills() {
        let start = Instant::now();
        let config = RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: 10,
                refill_time: Duration::from_secs(1),
                one_time_burst: 5,
            }),
            ops: None,
        };
        let mut limiter = RateLimiter::new(&config, start).unwrap();

        assert_eq!(limiter.try_consume_frame(15, start), Ok(()));
        let later = start + Duration::from_secs(60);
        assert_eq!(limiter.try_consume_frame(10, later), Ok(()));
        assert_eq!(
            limiter.try_consume_frame(1, later),
            Err(later + Duration::from_millis(100))
        );
    }

    #[test]
    fn full_bucket_does_not_bank_idle_refill() {
        let start = Instant::now();
        let config = RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size: 1,
                refill_time: Duration::from_secs(1),
                one_time_burst: 0,
            }),
            ops: None,
        };
        let mut limiter = RateLimiter::new(&config, start).unwrap();
        let idle = start + Duration::from_millis(1_999);

        assert_eq!(limiter.try_consume_frame(1, idle), Ok(()));
        assert_eq!(
            limiter.try_consume_frame(1, idle + Duration::from_millis(1)),
            Err(idle + Duration::from_secs(1))
        );
    }

    #[test]
    fn rejects_invalid_configurations() {
        let start = Instant::now();
        assert_eq!(
            RateLimiter::new(&RateLimiterConfig::default(), start).unwrap_err(),
            RateLimiterConfigError::Empty
        );

        let mut invalid = config((0, 0), 1);
        assert_eq!(
            RateLimiter::new(&invalid, start).unwrap_err(),
            RateLimiterConfigError::ZeroSize("bandwidth")
        );
        invalid.bandwidth.as_mut().unwrap().size = 1;
        invalid.ops.as_mut().unwrap().refill_time = Duration::ZERO;
        assert_eq!(
            RateLimiter::new(&invalid, start).unwrap_err(),
            RateLimiterConfigError::ZeroRefillTime("ops")
        );
    }
}
