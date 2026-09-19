//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_AGENTD_BYTES: usize = 128 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate that bytes contain an Agentd executable for the requested guest architecture.
pub(crate) fn validate_agentd(bytes: &[u8], expected_arch: &str) -> Result<(), String> {
    if bytes.len() < 64 {
        return Err("file is too small to be an ELF executable".into());
    }
    if bytes.len() > MAX_AGENTD_BYTES {
        return Err(format!(
            "file exceeds the {MAX_AGENTD_BYTES}-byte safety limit"
        ));
    }
    if &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("expected a 64-bit little-endian ELF executable".into());
    }

    let file_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if !matches!(file_type, 2 | 3) {
        return Err(format!(
            "ELF type {file_type} is not executable or position-independent"
        ));
    }

    let expected_machine = match expected_arch {
        "x86_64" => 62,
        "aarch64" => 183,
        architecture => return Err(format!("unsupported architecture {architecture}")),
    };
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != expected_machine {
        return Err(format!(
            "ELF machine {machine} does not match target architecture {expected_arch}"
        ));
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn executable_elf(machine: u16) -> [u8; 64] {
        let mut bytes = [0_u8; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_supported_target_architectures() {
        validate_agentd(&executable_elf(62), "x86_64").unwrap();
        validate_agentd(&executable_elf(183), "aarch64").unwrap();
    }

    #[test]
    fn rejects_target_architecture_mismatch() {
        let error = validate_agentd(&executable_elf(62), "aarch64").unwrap_err();
        assert!(error.contains("does not match target architecture aarch64"));
    }

    #[test]
    fn rejects_unknown_target_architecture() {
        let error = validate_agentd(&executable_elf(62), "riscv64").unwrap_err();
        assert_eq!(error, "unsupported architecture riscv64");
    }
}
