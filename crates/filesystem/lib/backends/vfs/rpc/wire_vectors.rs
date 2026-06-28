//! Cross-language CBOR wire fixtures shared with the Go `vfs` package.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::protocol::{
        PROTOCOL_VERSION, VfsRequest, encode_getattr, encode_getattr_many, encode_write, to_cbor,
    };
    use serde_bytes::ByteBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("lib/backends/vfs/rpc/testdata/wire_vectors.json")
    }

    fn hello_bytes() -> Vec<u8> {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(b"MVFS");
        buf[4..].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        buf.to_vec()
    }

    #[test]
    #[ignore = "run manually to refresh testdata/wire_vectors.json"]
    fn export_wire_vector_fixtures() {
        use std::fs;

        let path = fixture_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let file_path = b"/dir/file";
        let data = b"hello world payload";
        let fixtures = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "hello_hex": hex::encode(hello_bytes()),
            "getattr_hex": hex::encode(encode_getattr(file_path)),
            "write_hex": hex::encode(encode_write(b"/some/file", 42, data)),
            "getattr_many_hex": hex::encode(encode_getattr_many(&[b"/a", b"/bb"])),
            "statfs_hex": hex::encode(to_cbor(&VfsRequest::StatFs)),
            "flush_hex": hex::encode(to_cbor(&VfsRequest::Flush {
                path: ByteBuf::from(b"/f".to_vec()),
            })),
            "fsync_true_hex": hex::encode(to_cbor(&VfsRequest::Fsync {
                path: ByteBuf::from(b"/f".to_vec()),
                datasync: true,
            })),
            "fsync_false_hex": hex::encode(to_cbor(&VfsRequest::Fsync {
                path: ByteBuf::from(b"/f".to_vec()),
                datasync: false,
            })),
            "fsyncdir_hex": hex::encode(to_cbor(&VfsRequest::FsyncDir {
                path: ByteBuf::from(b"/d".to_vec()),
            })),
        });
        fs::write(path, serde_json::to_string_pretty(&fixtures).unwrap()).unwrap();
        let go_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/go/vfs/testdata/wire_vectors.json");
        if let Some(parent) = go_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(go_path, serde_json::to_string_pretty(&fixtures).unwrap());
    }

    #[test]
    fn wire_vector_fixtures_match_encoders() {
        let raw = std::fs::read_to_string(fixture_path()).expect("wire_vectors.json");
        let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("parse fixtures");

        assert_eq!(
            fixtures["protocol_version"].as_u64().unwrap() as u32,
            PROTOCOL_VERSION
        );
        assert_eq!(
            hex::decode(fixtures["hello_hex"].as_str().unwrap()).unwrap(),
            hello_bytes()
        );
        assert_eq!(
            hex::decode(fixtures["getattr_hex"].as_str().unwrap()).unwrap(),
            encode_getattr(b"/dir/file")
        );
        assert_eq!(
            hex::decode(fixtures["write_hex"].as_str().unwrap()).unwrap(),
            encode_write(b"/some/file", 42, b"hello world payload")
        );
        assert_eq!(
            hex::decode(fixtures["getattr_many_hex"].as_str().unwrap()).unwrap(),
            encode_getattr_many(&[b"/a", b"/bb"])
        );
        assert_eq!(
            hex::decode(fixtures["statfs_hex"].as_str().unwrap()).unwrap(),
            to_cbor(&VfsRequest::StatFs)
        );
        assert_eq!(
            hex::decode(fixtures["flush_hex"].as_str().unwrap()).unwrap(),
            to_cbor(&VfsRequest::Flush {
                path: ByteBuf::from(b"/f".to_vec()),
            })
        );
        assert_eq!(
            hex::decode(fixtures["fsync_true_hex"].as_str().unwrap()).unwrap(),
            to_cbor(&VfsRequest::Fsync {
                path: ByteBuf::from(b"/f".to_vec()),
                datasync: true,
            })
        );
        assert_eq!(
            hex::decode(fixtures["fsync_false_hex"].as_str().unwrap()).unwrap(),
            to_cbor(&VfsRequest::Fsync {
                path: ByteBuf::from(b"/f".to_vec()),
                datasync: false,
            })
        );
        assert_eq!(
            hex::decode(fixtures["fsyncdir_hex"].as_str().unwrap()).unwrap(),
            to_cbor(&VfsRequest::FsyncDir {
                path: ByteBuf::from(b"/d".to_vec()),
            })
        );

        // Guard against drift between borrowed and owned encoders (same bytes as fixtures).
        let owned_getattr = to_cbor(&VfsRequest::GetAttr {
            path: ByteBuf::from(b"/dir/file".to_vec()),
        });
        assert_eq!(
            owned_getattr,
            encode_getattr(b"/dir/file"),
            "owned GetAttr CBOR must match encode_getattr fast path"
        );
    }
}
