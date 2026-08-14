use napi_derive::napi;

use napi::bindgen_prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder grouping egress and ingress rate limits.
#[napi(js_name = "NetworkRateLimiterBuilder")]
pub struct JsNetworkRateLimiterBuilder {
    pub(crate) egress: Option<RateLimiterValues>,
    pub(crate) ingress: Option<RateLimiterValues>,
}

#[derive(Clone)]
pub(crate) struct RateLimiterValues {
    pub(crate) bandwidth: Option<(u64, u64)>,
    pub(crate) bandwidth_burst: Option<u64>,
    pub(crate) ops: Option<(u64, u64)>,
    pub(crate) ops_burst: Option<u64>,
}

/// Fluent builder for one direction's network rate limiter. Chainable
/// setters accumulate bucket values for `NetworkRateLimiterBuilder`.
#[napi(js_name = "RateLimiterBuilder")]
pub struct JsRateLimiterBuilder {
    pub(crate) bandwidth: Option<(u64, u64)>,
    pub(crate) bandwidth_burst: Option<u64>,
    pub(crate) ops: Option<(u64, u64)>,
    pub(crate) ops_burst: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRateLimiterBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            bandwidth: None,
            bandwidth_burst: None,
            ops: None,
            ops_burst: None,
        }
    }

    /// Cap bandwidth at `sizeBytes` bytes per `refillTimeMs` milliseconds.
    #[napi]
    pub fn bandwidth(&mut self, size_bytes: f64, refill_time_ms: f64) -> Result<&Self> {
        self.bandwidth = Some((
            whole_u64("sizeBytes", size_bytes)?,
            whole_u64("refillTimeMs", refill_time_ms)?,
        ));
        Ok(self)
    }

    /// Grant a one-time startup burst of `sizeBytes` bytes on top of the
    /// bandwidth bucket. Requires `bandwidth()`.
    #[napi(js_name = "bandwidthBurst")]
    pub fn bandwidth_burst(&mut self, size_bytes: f64) -> Result<&Self> {
        self.bandwidth_burst = Some(whole_u64("sizeBytes", size_bytes)?);
        Ok(self)
    }

    /// Cap packet rate at `count` frames per `refillTimeMs` milliseconds.
    #[napi]
    pub fn ops(&mut self, count: f64, refill_time_ms: f64) -> Result<&Self> {
        self.ops = Some((
            whole_u64("count", count)?,
            whole_u64("refillTimeMs", refill_time_ms)?,
        ));
        Ok(self)
    }

    /// Grant a one-time startup burst of `count` frames on top of the ops
    /// bucket. Requires `ops()`.
    #[napi(js_name = "opsBurst")]
    pub fn ops_burst(&mut self, count: f64) -> Result<&Self> {
        self.ops_burst = Some(whole_u64("count", count)?);
        Ok(self)
    }
}

#[napi]
impl JsNetworkRateLimiterBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            egress: None,
            ingress: None,
        }
    }

    /// Configure guest-to-runtime traffic limits.
    #[napi]
    pub fn egress(
        &mut self,
        env: &Env,
        configure: Function<
            ClassInstance<JsRateLimiterBuilder>,
            ClassInstance<JsRateLimiterBuilder>,
        >,
    ) -> Result<&Self> {
        let initial = JsRateLimiterBuilder::new().into_instance(env)?;
        let returned = configure.call(initial)?;
        self.egress = Some(returned.values());
        Ok(self)
    }

    /// Configure runtime-to-guest traffic limits.
    #[napi]
    pub fn ingress(
        &mut self,
        env: &Env,
        configure: Function<
            ClassInstance<JsRateLimiterBuilder>,
            ClassInstance<JsRateLimiterBuilder>,
        >,
    ) -> Result<&Self> {
        let initial = JsRateLimiterBuilder::new().into_instance(env)?;
        let returned = configure.call(initial)?;
        self.ingress = Some(returned.values());
        Ok(self)
    }
}

impl JsRateLimiterBuilder {
    fn values(&self) -> RateLimiterValues {
        RateLimiterValues {
            bandwidth: self.bandwidth,
            bandwidth_burst: self.bandwidth_burst,
            ops: self.ops,
            ops_burst: self.ops_burst,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a JS number to a whole non-negative u64, rejecting fractions,
/// negatives, and values beyond exact integer precision.
fn whole_u64(name: &str, value: f64) -> Result<u64> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0; // 2^53 - 1

    if !value.is_finite() || value.fract() != 0.0 || !(0.0..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(napi::Error::from_reason(format!(
            "{name} must be a non-negative integer"
        )));
    }
    Ok(value as u64)
}
