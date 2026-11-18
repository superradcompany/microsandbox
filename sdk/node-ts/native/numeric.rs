use napi::{Error, Result};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate before casting: N-API integer arguments otherwise wrap and truncate.
pub(crate) fn safe_integer(value: f64, name: &str) -> Result<u64> {
    if !value.is_finite() || value.fract() != 0.0 || !(0.0..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(Error::from_reason(format!(
            "{name} must be a non-negative safe integer"
        )));
    }
    Ok(value as u64)
}

pub(crate) fn uint32(value: f64, name: &str) -> Result<u32> {
    u32::try_from(safe_integer(value, name)?)
        .map_err(|_| Error::from_reason(format!("{name} out of u32 range")))
}
