//! Normalize the historical internal launcher without claiming user subcommands.
use std::ffi::OsString;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn normalize(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut args: Vec<_> = args.into_iter().collect();
    if args.get(1).is_some_and(|arg| arg == "sandbox")
        && args.iter().skip(2).any(|arg| arg == "--sandbox-id")
        && args
            .iter()
            .skip(2)
            .any(|arg| arg == "--config-fd" || arg == "--config-file")
    {
        args[1] = "machine".into();
    }
    args
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_historical_internal_launches_are_normalized() {
        let internal = ["msb", "sandbox", "--sandbox-id", "1", "--config-fd", "96"];
        assert_eq!(normalize(internal.map(OsString::from))[1], "machine");
        for argv in [
            vec!["msb", "sandbox", "list"],
            vec!["msb", "sandbox", "--help"],
            vec!["msb", "machine", "--help"],
        ] {
            let expected: Vec<_> = argv.into_iter().map(OsString::from).collect();
            assert_eq!(normalize(expected.clone()), expected);
        }
    }
}
