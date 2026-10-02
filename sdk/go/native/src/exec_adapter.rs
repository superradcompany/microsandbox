use std::os::raw::{c_char, c_uchar};

use base64::Engine;

use crate::{Handle, get, run_c};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the configured shell from the bound sandbox, including connected/restored handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_shell_path(
    cancel_id: u64,
    handle: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        Ok(Box::pin(async move {
            let shell = sandbox
                .config()
                .spec
                .runtime
                .shell
                .as_deref()
                .unwrap_or("/bin/sh");
            Ok(serde_json::json!({"shell": shell}).to_string())
        }))
    })
}

/// Retain legacy text fields for older Go readers; raw bytes use the same
/// base64 representation as streaming Collect, including empty streams.
pub(crate) fn collected_output_json(output: &microsandbox::sandbox::ExecOutput) -> String {
    collected_streams_json(
        output.stdout_bytes(),
        output.stderr_bytes(),
        output.status().code,
    )
}

fn collected_streams_json(stdout: &[u8], stderr: &[u8], exit_code: i32) -> String {
    serde_json::json!({
        "stdout": std::str::from_utf8(stdout).unwrap_or_default(),
        "stderr": std::str::from_utf8(stderr).unwrap_or_default(),
        "stdout_b64": base64::engine::general_purpose::STANDARD.encode(stdout),
        "stderr_b64": base64::engine::general_purpose::STANDARD.encode(stderr),
        "exit_code": exit_code,
    })
    .to_string()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct LegacyOutput {
        stdout: String,
        stderr: String,
        exit_code: i32,
    }

    #[test]
    fn collected_output_preserves_legacy_reader_contract() {
        let payload = collected_streams_json(b"hello\0world", b"error", 7);
        let old: LegacyOutput = serde_json::from_str(&payload).unwrap();
        assert_eq!(old.stdout, "hello\0world");
        assert_eq!(old.stderr, "error");
        assert_eq!(old.exit_code, 7);
    }

    #[test]
    fn binary_streams_are_lossless_without_redefining_legacy_fields() {
        let payload = collected_streams_json(b"a\xff\0b", b"c\xfe\0d", 7);
        let fields: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let old: LegacyOutput = serde_json::from_str(&payload).unwrap();
        // Old clients keep their existing behavior; new clients consume raw bytes.
        assert!(old.stdout.is_empty());
        assert!(old.stderr.is_empty());
        for (field, expected) in [("stdout_b64", b"a\xff\0b"), ("stderr_b64", b"c\xfe\0d")] {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(fields[field].as_str().unwrap())
                .unwrap();
            assert_eq!(bytes, expected);
        }
    }
}
