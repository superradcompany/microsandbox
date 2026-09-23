//! Static Linux guest fixture: prove execution and timer wakeups on a chosen CPU.

use std::fs;
use std::thread;
use std::time::{Duration, Instant};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

unsafe extern "C" {
    fn sched_setaffinity(pid: i32, size: usize, mask: *const u64) -> i32;
    fn sched_getcpu() -> i32;
}

fn main() -> std::io::Result<()> {
    let cpu: usize = std::env::args().nth(1).expect("CPU index").parse().unwrap();
    assert!(cpu < 64);
    let mask = 1_u64 << cpu;
    // A successful pin must be followed by observable execution on that CPU.
    if unsafe { sched_setaffinity(0, 8, &mask) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let start = Instant::now();
    for _ in 0..10 {
        assert_eq!(unsafe { sched_getcpu() }, cpu as i32);
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(unsafe { sched_getcpu() }, cpu as i32);
    let marker = fs::read_to_string("/dev/shm/cow-marker")?;
    assert_eq!(marker.trim(), "captured");
    println!("cpu={cpu} wakeups=10 elapsed_ms={}", start.elapsed().as_millis());
    Ok(())
}
