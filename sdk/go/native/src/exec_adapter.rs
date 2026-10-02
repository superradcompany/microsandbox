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

/// Retain legacy text fields for older Go readers. Only non-UTF-8 streams
/// need the additive base64 representation used by streaming Collect.
pub(crate) fn collected_output_json(output: &microsandbox::sandbox::ExecOutput) -> String {
    collected_streams_json(
        output.stdout_bytes(),
        output.stderr_bytes(),
        output.status().code,
    )
}

fn collected_streams_json(stdout: &[u8], stderr: &[u8], exit_code: i32) -> String {
    let stdout_text = std::str::from_utf8(stdout);
    let stderr_text = std::str::from_utf8(stderr);
    let mut payload = serde_json::json!({
        "stdout": stdout_text.unwrap_or_default(),
        "stderr": stderr_text.unwrap_or_default(),
        "exit_code": exit_code,
    });
    // Valid UTF-8, including NUL, round-trips through JSON without loss. Sending
    // a second copy would reduce the output that fits older callers' 1 MiB buffer.
    for (field, bytes, needs_base64) in [
        ("stdout_b64", stdout, stdout_text.is_err()),
        ("stderr_b64", stderr, stderr_text.is_err()),
    ] {
        if needs_base64 {
            payload[field] = base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into();
        }
    }
    payload.to_string()
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

    #[test]
    fn large_text_keeps_legacy_buffer_capacity() {
        let mut buffer = vec![0; 1 << 20];
        // Exercise both plain text near the limit and JSON-escaped text. Both
        // fit the old response but would overflow if also encoded as base64.
        for stdout in [vec![b'a'; (1 << 20) - 128], vec![0; 160 << 10]] {
            let payload = collected_streams_json(&stdout, b"error", 7);
            let legacy = serde_json::json!({
                "stdout": std::str::from_utf8(&stdout).unwrap(),
                "stderr": "error",
                "exit_code": 7,
            })
            .to_string();
            assert_eq!(payload, legacy);
            assert!(crate::write_output(buffer.as_mut_ptr(), buffer.len(), &payload).is_ok());
        }
    }

    #[test]
    fn mixed_streams_only_encode_the_non_utf8_stream() {
        for (stdout, stderr, encoded, text) in [
            (&b"text\0"[..], &b"\xff"[..], "stderr_b64", "stdout_b64"),
            (&b"\xff"[..], &b"text\0"[..], "stdout_b64", "stderr_b64"),
        ] {
            let payload: serde_json::Value =
                serde_json::from_str(&collected_streams_json(stdout, stderr, 0)).unwrap();
            assert_eq!(payload[encoded], "/w==");
            assert!(payload.get(text).is_none());
        }
    }
}
