//! Shared secret conventions.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build the default guest-visible placeholder for a secret environment variable.
pub fn default_placeholder(env_var: &str) -> String {
    format!("$MSB_{env_var}")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_placeholder_prefixes_environment_variable() {
        assert_eq!(default_placeholder("API_KEY"), "$MSB_API_KEY");
    }
}
