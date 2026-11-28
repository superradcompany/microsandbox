//! Host path encoding for the `tag:host[:opts]` mount wire format.

use crate::is_windows_drive_separator_at;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a host path contains a separator of the `tag:host[:opts]` mount
/// wire format: `,`, `;`, or a `:` other than a Windows drive colon (`C:\`)
/// on Windows. Such a path must travel encoded with [`encode_mount_host_path`].
pub fn mount_host_path_has_wire_separator(path: &str) -> bool {
    path.char_indices().any(|(index, c)| match c {
        ',' | ';' => true,
        ':' => !(cfg!(windows) && is_windows_drive_separator_at(path, index)),
        _ => false,
    })
}

/// Encode a host path for the `tag:host[:opts]` mount wire format.
///
/// The wire grammar separates fields with `:` and options with `,`, and lists
/// are joined with `;`. Host paths may legitimately contain all three (a
/// directory named "Smith, John"), so they can travel percent-encoded: `%`,
/// `,`, `;` and `:` become `%XX`. On Windows a drive colon (`C:\`) stays as
/// it is, since the Windows mount spec parsers already recognise it.
pub fn encode_mount_host_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, c) in path.char_indices() {
        match c {
            ':' if cfg!(windows) && is_windows_drive_separator_at(path, index) => out.push(':'),
            '%' => out.push_str("%25"),
            ',' => out.push_str("%2C"),
            ';' => out.push_str("%3B"),
            ':' => out.push_str("%3A"),
            c => out.push(c),
        }
    }

    out
}

/// Decode a host path written by [`encode_mount_host_path`].
///
/// Text without `%` decodes to itself, so hand-written specs such as
/// `tag:/host/data` or `tag:C:\data` keep working.
pub fn decode_mount_host_path(text: &str) -> Result<String, String> {
    if !text.contains('%') {
        return Ok(text.to_string());
    }

    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let escape = match bytes.get(index + 1..index + 3) {
                Some(&[high, low]) => hex_digit(high).zip(hex_digit(low)),
                _ => None,
            }
            .map(|(high, low)| high << 4 | low)
            .ok_or_else(|| format!("invalid percent escape in mount host path {text:?}"))?;
            out.push(escape);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(out).map_err(|_| format!("mount host path is not valid UTF-8: {text:?}"))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// The value of one ASCII hex digit. `u8::from_str_radix` is not used for
/// escapes because it also accepts a leading `+`.
fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_windows_drive_path_text;

    #[test]
    fn test_mount_host_path_round_trips_wire_separators() {
        for path in [
            "/Users/a/Smith, John",
            "/data/a;b/c:d",
            "/data/100% done",
            r"C:\Users\用户\a,b;c",
            r"C:\plain path",
            r"D:/x:y",
            "/data/%2C literal",
        ] {
            let encoded = encode_mount_host_path(path);

            let after_drive = if cfg!(windows) && is_windows_drive_path_text(path) {
                assert_eq!(&encoded[..2], &path[..2], "drive colon kept: {encoded}");
                &encoded[2..]
            } else {
                &encoded[..]
            };

            assert!(!after_drive.contains([',', ';', ':']), "{encoded}");
            assert_eq!(decode_mount_host_path(&encoded).unwrap(), path);
        }
    }

    #[test]
    fn test_mount_host_path_wire_separator_detection() {
        for path in [
            "/Users/a/Smith, John",
            "/data/a;b",
            "/data/c:d",
            r"C:\a\b:c",
        ] {
            assert!(mount_host_path_has_wire_separator(path), "{path}");
        }
        for path in ["/data/plain", "/data/100% done", "/x/My%20Files", ""] {
            assert!(!mount_host_path_has_wire_separator(path), "{path}");
        }
        assert_eq!(
            mount_host_path_has_wire_separator(r"C:\data"),
            !cfg!(windows),
            "a drive colon is a separator only off Windows"
        );
    }

    #[test]
    fn test_mount_host_path_decodes_raw_specs_and_rejects_bad_escapes() {
        assert_eq!(decode_mount_host_path("/host/data").unwrap(), "/host/data");
        assert_eq!(decode_mount_host_path(r"C:\data").unwrap(), r"C:\data");
        assert!(decode_mount_host_path("/a%2").is_err());
        assert!(decode_mount_host_path("/a%zz").is_err());
        assert!(decode_mount_host_path("/a%FF").is_err());
    }

    #[test]
    fn test_mount_host_path_escapes_are_exactly_two_hex_digits() {
        // A sign is not a hex digit, although u8::from_str_radix accepts "+A".
        for bad in ["/a%+A", "/a%+Ab", "/a%0", "/a%", "/a%zz", "/a% A", "/a%-1"] {
            assert!(
                decode_mount_host_path(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert_eq!(
            decode_mount_host_path("/a%2cb%2C%3a%3B%25").unwrap(),
            "/a,b,:;%"
        );
        assert_eq!(decode_mount_host_path("/%E7%94%A8").unwrap(), "/用");
    }
}
