//! The CLI version, stored as plain UTF-8 in a discoverable executable section.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Keep the emitter within the SDK reader's documented section-size limit.
const _: () = assert!(env!("CARGO_PKG_VERSION").len() <= 256);

// Keep this in the binary crate so Cargo supplies the CLI package version.
// Mach-O uses a segment/section pair; ELF and PE share a <= 8-byte section name.
#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__msbver"))]
#[cfg_attr(
    any(target_os = "linux", target_os = "windows"),
    unsafe(link_section = ".msbver")
)]
static MSB_VERSION: [u8; env!("CARGO_PKG_VERSION").len()] = version_bytes();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Supply Clap from the same bytes the SDK reads from the executable.
pub fn version() -> &'static str {
    // A live opaque reference keeps the section reachable through LTO and
    // linker garbage collection. `#[used]` alone only retains the object input.
    std::str::from_utf8(std::hint::black_box(&MSB_VERSION))
        .expect("Cargo package versions are UTF-8")
}

const fn version_bytes() -> [u8; env!("CARGO_PKG_VERSION").len()] {
    let source = env!("CARGO_PKG_VERSION").as_bytes();
    let mut bytes = [0; env!("CARGO_PKG_VERSION").len()];
    let mut index = 0;
    while index < source.len() {
        bytes[index] = source[index];
        index += 1;
    }
    bytes
}
