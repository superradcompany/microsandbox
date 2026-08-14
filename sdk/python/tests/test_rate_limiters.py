"""Unit tests for network rate limiter configuration."""

from __future__ import annotations

from microsandbox import Network, NetworkRateLimiter, RateLimiter, TokenBucket


def test_rate_limiters_serialize_both_buckets() -> None:
    network = Network(
        rate_limiter=NetworkRateLimiter(
            egress=RateLimiter(
                bandwidth=TokenBucket(
                    size=1_048_576, refill_time_ms=1_000, one_time_burst=524_288
                ),
                ops=TokenBucket(size=1_000, refill_time_ms=1_000, one_time_burst=500),
            ),
            ingress=RateLimiter(
                ops=TokenBucket(size=100, refill_time_ms=500),
            ),
        ),
    )

    d = network._to_dict()
    assert d["rate_limiter"]["egress"] == {
        "bandwidth": {
            "size": 1_048_576,
            "refill_time_ms": 1_000,
            "one_time_burst": 524_288,
        },
        "ops": {"size": 1_000, "refill_time_ms": 1_000, "one_time_burst": 500},
    }
    assert d["rate_limiter"]["ingress"] == {
        "ops": {"size": 100, "refill_time_ms": 500},
    }


def test_zero_burst_is_omitted_from_the_wire_dict() -> None:
    bucket = TokenBucket(size=10, refill_time_ms=100)
    assert bucket._to_dict() == {"size": 10, "refill_time_ms": 100}


def test_unset_rate_limiters_stay_off_the_wire() -> None:
    assert "rate_limiter" not in Network()._to_dict()
