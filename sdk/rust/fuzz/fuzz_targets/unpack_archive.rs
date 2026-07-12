//! Coverage-guided fuzzing of the snapshot import record walker: arbitrary bytes are fed
//! through the same unpack path `Snapshot::import` uses (decompression excluded — zstd has
//! its own fuzzing upstream; the walker is the code we own). Malformed input must produce
//! errors, never panics, overflows, or hangs.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;

static RT: OnceLock<Runtime> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fuzz runtime")
    });
    rt.block_on(microsandbox::snapshot::fuzz_unpack_archive(data));
});
