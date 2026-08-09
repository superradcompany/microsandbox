//! Canonical OCI default-command resolution.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An executable and argv resolved from an OCI entrypoint and command.
///
/// This is an internal cross-crate contract. SDKs expose execution methods rather than this type.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommand {
    /// Executable passed to the guest process launcher.
    pub program: String,

    /// Arguments passed after the executable.
    pub args: Vec<String>,
}

/// Errors produced while resolving an OCI default command.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandResolutionError {
    /// Neither the entrypoint nor the selected command supplies an executable.
    #[error(
        "sandbox has no default command; configure an entrypoint or cmd, or execute a literal command"
    )]
    NoDefaultCommand,

    /// An array selected an empty string as its executable.
    #[error("{origin} executable must not be empty")]
    EmptyExecutable {
        /// Configuration source containing the empty executable.
        origin: &'static str,
    },

    /// An argv token contains a NUL byte and cannot be passed to an operating system process API.
    #[error("{origin} token at index {index} contains a NUL byte")]
    NulByte {
        /// Configuration source containing the invalid token.
        origin: &'static str,

        /// Zero-based token index within that source.
        index: usize,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve an OCI default command from an effective entrypoint, stored CMD, and optional CMD override.
///
/// `cmd_override = Some(values)` replaces the stored CMD, including an empty override which clears
/// CMD for this invocation. No shell parsing or string concatenation is performed.
#[doc(hidden)]
pub fn resolve_default_command(
    entrypoint: Option<&[String]>,
    cmd: Option<&[String]>,
    cmd_override: Option<&[String]>,
) -> Result<ResolvedCommand, CommandResolutionError> {
    let entrypoint = entrypoint.filter(|tokens| !tokens.is_empty());
    let (selected_cmd, cmd_source) = match cmd_override {
        Some(tokens) => (Some(tokens), "cmd override"),
        None => (cmd, "cmd"),
    };
    let selected_cmd = selected_cmd.filter(|tokens| !tokens.is_empty());

    if let Some(tokens) = entrypoint {
        validate_tokens("entrypoint", tokens)?;
        if let Some(tokens) = selected_cmd {
            validate_tokens(cmd_source, tokens)?;
        }

        return Ok(ResolvedCommand {
            program: tokens[0].clone(),
            args: tokens[1..]
                .iter()
                .chain(selected_cmd.into_iter().flatten())
                .cloned()
                .collect(),
        });
    }

    let Some(tokens) = selected_cmd else {
        return Err(CommandResolutionError::NoDefaultCommand);
    };
    validate_tokens(cmd_source, tokens)?;

    Ok(ResolvedCommand {
        program: tokens[0].clone(),
        args: tokens[1..].to_vec(),
    })
}

fn validate_tokens(origin: &'static str, tokens: &[String]) -> Result<(), CommandResolutionError> {
    if tokens.first().is_some_and(String::is_empty) {
        return Err(CommandResolutionError::EmptyExecutable { origin });
    }

    if let Some(index) = tokens.iter().position(|token| token.contains('\0')) {
        return Err(CommandResolutionError::NulByte { origin, index });
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{CommandResolutionError, ResolvedCommand, resolve_default_command};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn resolves_required_oci_command_matrix() {
        struct Case {
            entrypoint: Option<Vec<String>>,
            cmd: Option<Vec<String>>,
            cmd_override: Option<Vec<String>>,
            expected: Result<ResolvedCommand, CommandResolutionError>,
        }

        let cases = [
            Case {
                entrypoint: None,
                cmd: None,
                cmd_override: None,
                expected: Err(CommandResolutionError::NoDefaultCommand),
            },
            Case {
                entrypoint: None,
                cmd: Some(strings(&["a", "b"])),
                cmd_override: None,
                expected: Ok(ResolvedCommand {
                    program: "a".into(),
                    args: strings(&["b"]),
                }),
            },
            Case {
                entrypoint: Some(strings(&["e", "x"])),
                cmd: None,
                cmd_override: None,
                expected: Ok(ResolvedCommand {
                    program: "e".into(),
                    args: strings(&["x"]),
                }),
            },
            Case {
                entrypoint: Some(strings(&["e", "x"])),
                cmd: Some(strings(&["c", "y"])),
                cmd_override: None,
                expected: Ok(ResolvedCommand {
                    program: "e".into(),
                    args: strings(&["x", "c", "y"]),
                }),
            },
            Case {
                entrypoint: Some(strings(&["e", "x"])),
                cmd: Some(strings(&["c", "y"])),
                cmd_override: Some(strings(&["u", "v"])),
                expected: Ok(ResolvedCommand {
                    program: "e".into(),
                    args: strings(&["x", "u", "v"]),
                }),
            },
            Case {
                entrypoint: None,
                cmd: Some(strings(&["c", "y"])),
                cmd_override: Some(strings(&["u", "v"])),
                expected: Ok(ResolvedCommand {
                    program: "u".into(),
                    args: strings(&["v"]),
                }),
            },
            Case {
                entrypoint: Some(strings(&["e", "x"])),
                cmd: Some(strings(&["c", "y"])),
                cmd_override: Some(Vec::new()),
                expected: Ok(ResolvedCommand {
                    program: "e".into(),
                    args: strings(&["x"]),
                }),
            },
            Case {
                entrypoint: None,
                cmd: Some(strings(&["c", "y"])),
                cmd_override: Some(Vec::new()),
                expected: Err(CommandResolutionError::NoDefaultCommand),
            },
        ];

        for case in cases {
            assert_eq!(
                resolve_default_command(
                    case.entrypoint.as_deref(),
                    case.cmd.as_deref(),
                    case.cmd_override.as_deref(),
                ),
                case.expected
            );
        }
    }

    #[test]
    fn rejects_empty_executable_and_nul_tokens() {
        assert_eq!(
            resolve_default_command(Some(&strings(&[""])), None, None),
            Err(CommandResolutionError::EmptyExecutable {
                origin: "entrypoint"
            })
        );
        assert_eq!(
            resolve_default_command(None, Some(&strings(&["echo", "bad\0arg"])), None),
            Err(CommandResolutionError::NulByte {
                origin: "cmd",
                index: 1
            })
        );
    }
}
