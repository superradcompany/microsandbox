//! Entry point for the `runmsb` OCI runtime binary.

#[cfg(target_os = "linux")]
mod linux;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("runmsb is only supported on Linux hosts");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}
