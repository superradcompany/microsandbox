//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Match the common Unix main-thread stack reserve without committing it up front.
const WINDOWS_STACK_RESERVE_BYTES: usize = 8 * 1024 * 1024;
const WINDOWS_STACK_COMMIT_BYTES: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() == Some(std::ffi::OsStr::new("windows"))
        && std::env::var_os("CARGO_CFG_TARGET_ENV").as_deref() == Some(std::ffi::OsStr::new("msvc"))
    {
        // MSVC defaults executable main threads to a 1 MiB stack. Image materialization walks
        // realistic filesystem trees deeply enough for unoptimized Windows builds to exhaust it.
        // Reserve address space comparable to Unix while keeping the initial physical commit low.
        println!(
            "cargo:rustc-link-arg-bin=msb=/STACK:{WINDOWS_STACK_RESERVE_BYTES},{WINDOWS_STACK_COMMIT_BYTES}"
        );
    }
}
