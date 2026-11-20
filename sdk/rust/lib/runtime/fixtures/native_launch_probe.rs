//! Standalone native executable for launch-admission tests; compiled with rustc.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[used]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__msbver"))]
#[cfg_attr(not(target_os = "macos"), unsafe(link_section = ".msbver"))]
static VERSION: [u8; 6] = *b"0.7.16";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            let version = std::str::from_utf8(std::hint::black_box(&VERSION)).unwrap();
            println!("msb {version}");
        }
        Some("__launch-protocol") => {
            let path = std::env::current_exe().unwrap().with_extension("json");
            print!("{}", std::fs::read_to_string(path).unwrap());
        }
        _ => std::process::exit(97),
    }
}
