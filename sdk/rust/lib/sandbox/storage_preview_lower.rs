//! Rebuild the released runtime's manifest-keyed EROFS disk from private copies of its extents.

use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use microsandbox_image::{Digest, write_vmdk_descriptor};
use sha2::{Digest as _, Sha256};

use super::unavailable;
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct CapturedLower {
    pub(super) disk: PathBuf,
    cache: PathBuf,
    descriptor: (PathBuf, [u8; 32]),
    extents: Vec<(PathBuf, [u8; 32])>,
    _directory: tempfile::TempDir,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapturedLower {
    pub(super) fn capture(cache: &Path, manifest: &str, parent: &Path) -> MicrosandboxResult<Self> {
        let digest: Digest = manifest.parse().map_err(unavailable)?;
        if digest.algorithm() != "sha256" || !hex_digest(digest.hex()) {
            return Err(unavailable("invalid persisted OCI manifest digest"));
        }
        let canonical = fs::canonicalize(cache)
            .map_err(|_| unavailable("exact OCI lower is absent from the local cache"))?;
        let key = digest.to_path_safe();
        let descriptor = PathBuf::from("vmdk").join(format!("{key}.vmdk"));
        let mut bytes = Vec::new();
        cache_file(cache, &descriptor)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > 1024 * 1024 {
            return Err(unavailable("OCI lower descriptor exceeds 1 MiB"));
        }
        let text = std::str::from_utf8(&bytes).map_err(unavailable)?;
        let relative = extent_paths(&canonical, &key, text)?;
        let temp = tempfile::Builder::new()
            .prefix("lower-")
            .tempdir_in(parent)
            .map_err(unavailable)?;
        let mut extents = Vec::new();
        let mut extent_names = std::collections::BTreeMap::new();
        let mut copies = Vec::new();
        let mut total = 0_u64;
        for (i, rel) in relative.iter().enumerate() {
            let mut source = cache_file(cache, rel)?;
            let length = source.metadata().map_err(unavailable)?.len();
            total = total.saturating_add(length);
            if length == 0 || length % 512 != 0 || total > 64 * 1024u64.pow(4) {
                return Err(unavailable("OCI lower exceeds supported extent bounds"));
            }
            let copy = temp.path().join(format!("extent-{i}.erofs"));
            let output = File::options()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&copy)
                .map_err(unavailable)?;
            microsandbox_utils::copy::copy_file_handles(&source, &output).map_err(unavailable)?;
            let hash = file_digest(output)?;
            source.rewind().map_err(unavailable)?;
            if file_digest(source)? != hash {
                return Err(unavailable("cached OCI lower changed during capture"));
            }
            extents.push((rel.clone(), hash));
            let copy_path = fs::canonicalize(&copy).map_err(unavailable)?;
            extent_names.insert(copy_path, canonical.join(rel));
            copies.push(copy);
        }
        // Reproduce the producer's exact generated descriptor. Reject alternate modes, arbitrary
        // offsets, sectors, reordered fragments, extra directives and noncanonical aliases.
        let disk = temp.path().join("private.vmdk");
        write_vmdk_descriptor(
            &disk,
            &copies.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
        )
        .map_err(unavailable)?;
        let generated = fs::read_to_string(&disk).map_err(unavailable)?;
        let mut expected = String::new();
        for line in generated.lines() {
            if line.starts_with("RW ") {
                let (prefix, extent) = line
                    .split_once(" FLAT \"")
                    .ok_or_else(|| unavailable("invalid generated OCI lower"))?;
                let (path, offset) = extent
                    .rsplit_once("\" ")
                    .ok_or_else(|| unavailable("invalid generated extent"))?;
                let original = extent_names
                    .get(Path::new(path))
                    .ok_or_else(|| unavailable("invalid private extent identity"))?;
                use std::fmt::Write;
                writeln!(
                    expected,
                    "{prefix} FLAT \"{}\" {offset}",
                    original.display()
                )
                .map_err(unavailable)?;
            } else {
                expected.push_str(line);
                expected.push('\n');
            }
        }
        if expected != text {
            return Err(unavailable(
                "OCI lower descriptor does not match the supported materializer",
            ));
        }
        Ok(Self {
            disk,
            cache: cache.to_owned(),
            descriptor: (descriptor, Sha256::digest(&bytes).into()),
            extents,
            _directory: temp,
        })
    }

    pub(super) fn verify(&self) -> MicrosandboxResult<()> {
        // The runtime will next open the manifest-keyed cache. Refuse a changed image even if
        // the operator's selected mutable upper still has the same disk identity.
        for (relative, expected) in std::iter::once(&self.descriptor).chain(&self.extents) {
            if file_digest(cache_file(&self.cache, relative)?)? != *expected {
                return Err(unavailable(
                    "exact OCI lower changed since it was inspected; reopen recovery",
                ));
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn extent_paths(cache: &Path, key: &str, text: &str) -> MicrosandboxResult<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for line in text.lines().filter_map(|s| s.strip_prefix("RW ")) {
        let (_, value) = line
            .split_once(" FLAT \"")
            .ok_or_else(|| unavailable("unsupported OCI lower extent"))?;
        let (path, offset) = value
            .rsplit_once("\" ")
            .ok_or_else(|| unavailable("invalid OCI lower extent"))?;
        let offset: u64 = offset.parse().map_err(unavailable)?;
        let relative = Path::new(path)
            .strip_prefix(cache)
            .map_err(|_| unavailable("OCI lower extent outside the configured cache"))?;
        let mut components = relative.components();
        let (
            Some(std::path::Component::Normal(dir)),
            Some(std::path::Component::Normal(name)),
            None,
        ) = (components.next(), components.next(), components.next())
        else {
            return Err(unavailable("invalid cached OCI lower extent location"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| unavailable("invalid cached OCI extent name"))?;
        let first = paths.is_empty();
        let valid_meta = dir == "fsmeta" && name == format!("{key}.erofs");
        let valid_layer = dir == "layers"
            && name
                .strip_prefix("sha256_")
                .and_then(|s| s.strip_suffix(".erofs"))
                .is_some_and(hex_digest);
        if offset == 0 {
            if (first && !valid_meta) || (!first && !valid_layer) || paths.len() >= 1024 {
                return Err(unavailable("unexpected extent in manifest-keyed OCI lower"));
            }
            paths.push(relative.to_owned());
        } else if paths.last().is_none_or(|p| p != relative) {
            return Err(unavailable("invalid continuation in cached OCI lower"));
        }
    }
    if paths.is_empty() {
        return Err(unavailable("empty OCI lower descriptor"));
    }
    Ok(paths)
}

fn cache_file(cache: &Path, relative: &Path) -> MicrosandboxResult<File> {
    let file =
        microsandbox_runtime::checkpoint::migration::open_preview_cache_file(cache, relative)
            .map_err(unavailable)?;
    let metadata = file.metadata().map_err(unavailable)?;
    if !metadata.is_file() || metadata.len() > 64 * 1024u64.pow(4) {
        return Err(unavailable(
            "cached OCI lower is not a bounded regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(unavailable("cached OCI extent is a reparse point"));
        }
    }
    Ok(file)
}

fn file_digest(mut file: File) -> MicrosandboxResult<[u8; 32]> {
    file.rewind().map_err(unavailable)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(unavailable)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        microsandbox_runtime::checkpoint::migration::private_preview_parent().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn storage_preview_lower_0002_requires_private_traversal_and_a_single_link() {
        use microsandbox_runtime::checkpoint::migration::open_preview_cache_file;
        use std::os::unix::fs::PermissionsExt;
        // A separate direct child of sticky /tmp has no private ancestor besides itself.
        let cache = tempfile::tempdir_in("/tmp").unwrap();
        let role = cache.path().join("layers");
        fs::create_dir(&role).unwrap();
        let relative = PathBuf::from("layers").join(format!("sha256_{}.erofs", "a".repeat(64)));
        let source = cache.path().join(&relative);
        fs::write(&source, [0; 512]).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o664)).unwrap();
        fs::set_permissions(&role, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_preview_cache_file(cache.path(), &relative).is_err());
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700)).unwrap();
        open_preview_cache_file(cache.path(), &relative).unwrap();
        let alias = cache.path().join("another-name");
        fs::hard_link(&source, &alias).unwrap();
        assert!(open_preview_cache_file(cache.path(), &relative).is_err());
        fs::remove_file(alias).unwrap();
        #[cfg(target_os = "macos")]
        {
            let grant = std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(&source)
                .status()
                .unwrap();
            assert!(grant.success());
            assert!(open_preview_cache_file(cache.path(), &relative).is_err());
        }
    }

    #[test]
    fn storage_preview_lower_matches_exact_cached_descriptor_and_refuses_changed_bytes() {
        let cache = private_dir();
        let scratch = private_dir();
        for dir in ["fsmeta", "layers", "vmdk"] {
            fs::create_dir(cache.path().join(dir)).unwrap();
        }
        let manifest = "a".repeat(64);
        let meta = cache.path().join(format!("fsmeta/sha256_{manifest}.erofs"));
        let layer = cache
            .path()
            .join(format!("layers/sha256_{}.erofs", "b".repeat(64)));
        fs::write(&meta, [1; 512]).unwrap();
        fs::write(&layer, [2; 512]).unwrap();
        let desc = cache.path().join(format!("vmdk/sha256_{manifest}.vmdk"));
        write_vmdk_descriptor(&desc, &[&meta, &layer]).unwrap();
        #[cfg(unix)]
        for artifact in [&desc, &meta, &layer] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(artifact, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let lower =
            CapturedLower::capture(cache.path(), &format!("sha256:{manifest}"), scratch.path())
                .unwrap();
        lower.verify().unwrap();
        let private = fs::read_to_string(&lower.disk).unwrap();
        assert!(
            !private.contains(meta.to_str().unwrap()) && !private.contains(layer.to_str().unwrap())
        );
        fs::write(&layer, [3; 512]).unwrap();
        assert!(lower.verify().is_err());
        fs::remove_file(&desc).unwrap();
        assert!(
            CapturedLower::capture(cache.path(), &format!("sha256:{manifest}"), scratch.path())
                .is_err()
        );
    }

    #[test]
    fn storage_preview_lower_rejects_foreign_extents_and_noncanonical_descriptors() {
        let cache = private_dir();
        let scratch = private_dir();
        for dir in ["fsmeta", "layers", "vmdk"] {
            fs::create_dir(cache.path().join(dir)).unwrap();
        }
        let manifest = "a".repeat(64);
        let meta = cache.path().join(format!("fsmeta/sha256_{manifest}.erofs"));
        let desc = cache.path().join(format!("vmdk/sha256_{manifest}.vmdk"));
        let foreign = scratch.path().join("not-an-image");
        fs::write(&meta, [1; 512]).unwrap();
        fs::write(&foreign, [2; 512]).unwrap();
        write_vmdk_descriptor(&desc, &[&meta, &foreign]).unwrap();
        assert!(
            CapturedLower::capture(cache.path(), &format!("sha256:{manifest}"), scratch.path())
                .is_err()
        );
        write_vmdk_descriptor(&desc, &[&meta]).unwrap();
        let altered = fs::read_to_string(&desc).unwrap().replace("RW 1 ", "RW 2 ");
        fs::write(desc, altered).unwrap();
        assert!(
            CapturedLower::capture(cache.path(), &format!("sha256:{manifest}"), scratch.path())
                .is_err()
        );
    }
}
