//! Bounded, read-only sampling of optional kernel readiness attributes.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use microsandbox_protocol::resources::{
    CpuReadiness, MemoryReadiness, ObservationUnavailable, ObserveResources, ObservedResources,
    ResourceObservation,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEVICE_ROOT: &str = "/sys/bus/virtio/devices";
const MAX_DEVICES: usize = 4096;
const MAX_RECORD_BYTES: u64 = 512;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn observe(request: ObserveResources) -> ObservedResources {
    observe_at(Path::new(DEVICE_ROOT), request)
}

fn observe_at(root: &Path, request: ObserveResources) -> ObservedResources {
    let (cpu, memory) = match inventory(root) {
        Ok(devices) => (
            sample(&devices, "msb_cpu_readiness", parse_cpu),
            sample(&devices, "msb_memory_readiness", parse_memory),
        ),
        Err(reason) => (unavailable(reason), unavailable(reason)),
    };
    ObservedResources {
        query_id: request.query_id,
        cpu,
        memory,
    }
}

fn inventory(root: &Path) -> Result<Vec<PathBuf>, ObservationUnavailable> {
    let entries = fs::read_dir(root).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => ObservationUnavailable::Unsupported,
        _ => ObservationUnavailable::Io,
    })?;
    let mut devices = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DEVICES {
            return Err(ObservationUnavailable::Invalid);
        }
        let entry = entry.map_err(|_| ObservationUnavailable::Io)?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("virtio"))
        {
            devices.push(entry.path());
        }
    }
    Ok(devices)
}

fn sample<T>(
    devices: &[PathBuf],
    attribute: &str,
    parse: fn(&str) -> Result<T, ObservationUnavailable>,
) -> ResourceObservation<T> {
    let mut found = None;
    for device in devices {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(device.join(attribute))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return unavailable(read_error(&error)),
        };
        // Even a busy or invalid matching device participates in ambiguity. Never choose the
        // first readable record and silently associate another device with the host's operation.
        if found.is_some() {
            return unavailable(ObservationUnavailable::Ambiguous);
        }
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return unavailable(ObservationUnavailable::Invalid);
        }
        let mut bytes = Vec::new();
        let result = file
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| read_error(&error))
            .and_then(|_| {
                if bytes.len() as u64 > MAX_RECORD_BYTES {
                    return Err(ObservationUnavailable::Invalid);
                }
                let text =
                    std::str::from_utf8(&bytes).map_err(|_| ObservationUnavailable::Invalid)?;
                parse(text)
            });
        found = Some(result);
    }
    match found {
        Some(Ok(value)) => ResourceObservation::Available { value },
        Some(Err(reason)) => unavailable(reason),
        None => unavailable(ObservationUnavailable::Unsupported),
    }
}

fn read_error(error: &io::Error) -> ObservationUnavailable {
    match error.raw_os_error() {
        Some(libc::EAGAIN) => ObservationUnavailable::Busy,
        Some(libc::EOPNOTSUPP) => ObservationUnavailable::Unsupported,
        Some(libc::EPROTO) => ObservationUnavailable::Invalid,
        _ => ObservationUnavailable::Io,
    }
}

fn unavailable<T>(reason: ObservationUnavailable) -> ResourceObservation<T> {
    ResourceObservation::Unavailable { reason }
}

fn record<'a>(
    text: &'a str,
    keys: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, ObservationUnavailable> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    if !text.is_ascii() || text.chars().any(|c| c.is_ascii_control()) {
        return Err(ObservationUnavailable::Invalid);
    }
    let mut fields = Vec::new();
    for token in text.split(' ') {
        let (key, value) = token
            .split_once('=')
            .ok_or(ObservationUnavailable::Invalid)?;
        if fields.iter().any(|(previous, _)| *previous == key) {
            return Err(ObservationUnavailable::Invalid);
        }
        fields.push((key, value));
    }
    if number(field(&fields, "schema")?)? != 1 {
        return Err(ObservationUnavailable::Unsupported);
    }
    if fields.len() != keys.len() || fields.iter().any(|(key, _)| !keys.contains(key)) {
        return Err(ObservationUnavailable::Invalid);
    }
    Ok(fields)
}

fn field<'a>(fields: &[(&str, &'a str)], key: &str) -> Result<&'a str, ObservationUnavailable> {
    fields
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| *value)
        .ok_or(ObservationUnavailable::Invalid)
}

fn number(value: &str) -> Result<u64, ObservationUnavailable> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ObservationUnavailable::Invalid);
    }
    value.parse().map_err(|_| ObservationUnavailable::Invalid)
}

fn boolean(value: &str) -> Result<bool, ObservationUnavailable> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(ObservationUnavailable::Invalid),
    }
}

fn parse_cpu(text: &str) -> Result<CpuReadiness, ObservationUnavailable> {
    let fields = record(
        text,
        &[
            "schema",
            "possible",
            "requested_online",
            "actual_online",
            "exact",
        ],
    )?;
    let count = |key| {
        number(field(&fields, key)?)?
            .try_into()
            .map_err(|_| ObservationUnavailable::Invalid)
    };
    let value = CpuReadiness {
        possible: count("possible")?,
        requested_online: count("requested_online")?,
        actual_online: count("actual_online")?,
        exact: boolean(field(&fields, "exact")?)?,
    };
    if !value.is_valid() {
        return Err(ObservationUnavailable::Invalid);
    }
    Ok(value)
}

fn parse_memory(text: &str) -> Result<MemoryReadiness, ObservationUnavailable> {
    let fields = record(
        text,
        &[
            "schema",
            "addr",
            "region_size",
            "requested_size",
            "plugged_size",
            "all_online",
        ],
    )?;
    let value = MemoryReadiness {
        address: number(field(&fields, "addr")?)?,
        region_size: number(field(&fields, "region_size")?)?,
        requested_size: number(field(&fields, "requested_size")?)?,
        plugged_size: number(field(&fields, "plugged_size")?)?,
        all_online: boolean(field(&fields, "all_online")?)?,
    };
    if !value.is_valid() {
        return Err(ObservationUnavailable::Invalid);
    }
    Ok(value)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const CPU: &str = "schema=1 possible=4 requested_online=2 actual_online=2 exact=1\n";
    const MEMORY: &str = "schema=1 addr=4294967296 region_size=536870912 requested_size=268435456 plugged_size=268435456 all_online=0\n";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "msb-resource-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, device: &str, attribute: &str, bytes: impl AsRef<[u8]>) {
            fs::create_dir_all(self.0.join(device)).unwrap();
            fs::write(self.0.join(device).join(attribute), bytes).unwrap();
        }

        fn observe(&self) -> ObservedResources {
            observe_at(&self.0, ObserveResources { query_id: [7; 16] })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn independent_availability_and_query_echo_are_not_fabricated() {
        let f = Fixture::new();
        f.write("virtio1", "msb_memory_readiness", MEMORY);
        let result = f.observe();
        assert_eq!(result.query_id, [7; 16]);
        assert_eq!(result.cpu, unavailable(ObservationUnavailable::Unsupported));
        assert!(matches!(
            result.memory,
            ResourceObservation::Available {
                value: MemoryReadiness {
                    all_online: false,
                    ..
                }
            }
        ));
        f.write("virtio2", "msb_cpu_readiness", CPU);
        assert!(matches!(
            f.observe().cpu,
            ResourceObservation::Available { .. }
        ));
        // Reads are per-query, not retained across a failed or disappearing device.
        fs::remove_file(f.0.join("virtio1/msb_memory_readiness")).unwrap();
        assert_eq!(
            f.observe().memory,
            unavailable(ObservationUnavailable::Unsupported)
        );
    }

    #[test]
    fn multiple_devices_never_select_the_first_readable_record() {
        let f = Fixture::new();
        f.write("virtio0", "msb_cpu_readiness", "invalid");
        f.write("virtio1", "msb_cpu_readiness", CPU);
        assert_eq!(
            f.observe().cpu,
            unavailable(ObservationUnavailable::Ambiguous)
        );
    }

    #[test]
    fn read_bounds_encoding_and_attribute_substitution_fail_closed() {
        let f = Fixture::new();
        f.write(
            "virtio0",
            "msb_cpu_readiness",
            vec![b'x'; MAX_RECORD_BYTES as usize + 1],
        );
        assert_eq!(
            f.observe().cpu,
            unavailable(ObservationUnavailable::Invalid)
        );
        f.write("virtio0", "msb_cpu_readiness", [255, 254]);
        assert_eq!(
            f.observe().cpu,
            unavailable(ObservationUnavailable::Invalid)
        );
        fs::remove_file(f.0.join("virtio0/msb_cpu_readiness")).unwrap();
        fs::write(f.0.join("other"), CPU).unwrap();
        symlink(f.0.join("other"), f.0.join("virtio0/msb_cpu_readiness")).unwrap();
        assert_eq!(f.observe().cpu, unavailable(ObservationUnavailable::Io));
    }

    #[test]
    fn cpu_validation_distinguishes_wrong_set_from_impossible_record() {
        assert!(parse_cpu(CPU).unwrap().exact);
        assert!(!parse_cpu(&CPU.replace("exact=1", "exact=0")).unwrap().exact);
        for text in [
            CPU.replace("actual_online=2", "actual_online=1"),
            CPU.replace("possible=4", "possible=1"),
            CPU.replace("possible=4", "possible=4294967296"),
            CPU.replace("requested_online=2", "requested_online=0"),
            CPU.replace("actual_online=2", "actual_online=0"),
            CPU.replace("exact=1", "exact=2"),
        ] {
            assert_eq!(parse_cpu(&text), Err(ObservationUnavailable::Invalid));
        }
    }

    #[test]
    fn memory_target_equality_does_not_replace_guest_onlining() {
        let value = parse_memory(MEMORY).unwrap();
        assert_eq!(value.requested_size, value.plugged_size);
        assert!(!value.all_online);
        let pending = MEMORY
            .replace("requested_size=268435456", "requested_size=0")
            .replace("all_online=0", "all_online=1");
        assert!(parse_memory(&pending).unwrap().all_online);
        for text in [
            MEMORY.replace("region_size=536870912", "region_size=1"),
            MEMORY.replace("region_size=536870912", "region_size=0"),
            MEMORY.replace("addr=4294967296", "addr=18446744073709551615"),
            MEMORY.replace("plugged_size=268435456", "plugged_size=-1"),
        ] {
            assert_eq!(parse_memory(&text), Err(ObservationUnavailable::Invalid));
        }
    }

    #[test]
    fn version_missing_duplicate_unknown_and_malformed_fields_refuse() {
        assert_eq!(
            parse_cpu(&CPU.replace("schema=1", "schema=2")),
            Err(ObservationUnavailable::Unsupported)
        );
        for text in [
            CPU.replace("schema=1 ", ""),
            format!("schema=1 {CPU}"),
            CPU.replace("exact=1", "unknown=1"),
            CPU.replace("possible=4", "possible=+4"),
            CPU.replace("possible=4", "possible="),
            CPU.replace(' ', "\n"),
            format!("{CPU}\n"),
        ] {
            assert_eq!(parse_cpu(&text), Err(ObservationUnavailable::Invalid));
        }
    }

    #[test]
    fn kernel_errors_do_not_claim_resize_refusal() {
        assert_eq!(
            read_error(&io::Error::from_raw_os_error(libc::EAGAIN)),
            ObservationUnavailable::Busy
        );
        assert_eq!(
            read_error(&io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
            ObservationUnavailable::Unsupported
        );
        assert_eq!(
            read_error(&io::Error::from_raw_os_error(libc::EPROTO)),
            ObservationUnavailable::Invalid
        );
        assert_eq!(
            read_error(&io::Error::from_raw_os_error(libc::EIO)),
            ObservationUnavailable::Io
        );
    }
}
