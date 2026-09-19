//! Bounded object verification with construction-thread-only consumption.

use std::io;
use std::sync::mpsc;
use std::time::Instant;

use microsandbox_image::checkpoint::{CheckpointObjectReadTiming, ObjectId};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_READERS: usize = 4;
const MAX_OBJECT_BYTES: usize = 32 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(super) struct ObjectPipelineTiming {
    /// Sum of worker read times; parallel worker times are not pipeline wall time.
    pub read_us: u128,
    pub hash_us: u128,
    pub consume_us: u128,
    pub elapsed_us: u128,
    pub object_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Verify at most four objects ahead, returning each buffer to its reader after consumption.
///
/// Only the invoking thread consumes bytes. Reader completion order may differ from object-ID
/// order, so callers must supply disjoint destination slices. On any error, dropping the work
/// channels cancels queued work and all active readers are joined before their inputs disappear.
pub(super) fn consume_verified_objects<T: Send>(
    objects: impl IntoIterator<Item = (ObjectId, T)>,
    read: impl Fn(&ObjectId, &mut Vec<u8>) -> io::Result<CheckpointObjectReadTiming> + Sync,
    mut consume: impl FnMut(T, &[u8]) -> io::Result<()>,
) -> io::Result<ObjectPipelineTiming> {
    let objects: Vec<_> = objects.into_iter().collect();
    let readers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(MAX_READERS)
        .min(objects.len());
    run_pipeline(objects, readers, &read, &mut consume)
}

fn run_pipeline<T: Send>(
    objects: Vec<(ObjectId, T)>,
    readers: usize,
    read: &(impl Fn(&ObjectId, &mut Vec<u8>) -> io::Result<CheckpointObjectReadTiming> + Sync),
    consume: &mut impl FnMut(T, &[u8]) -> io::Result<()>,
) -> io::Result<ObjectPipelineTiming> {
    let started = Instant::now();
    if objects.is_empty() {
        return Ok(ObjectPipelineTiming::default());
    }
    let readers = readers.clamp(1, MAX_READERS).min(objects.len());
    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = mpsc::sync_channel(readers);
        let mut senders = Vec::with_capacity(readers);
        let mut handles = Vec::with_capacity(readers);
        for worker in 0..readers {
            let (work_tx, work_rx) = mpsc::sync_channel::<(ObjectId, T, Vec<u8>)>(1);
            let ready_tx = ready_tx.clone();
            let handle = std::thread::Builder::new()
                .name("checkpoint-reader".into())
                .spawn_scoped(scope, move || {
                    while let Ok((id, item, mut bytes)) = work_rx.recv() {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            read(&id, &mut bytes)
                        }))
                        .unwrap_or_else(|_| Err(io::Error::other("checkpoint reader panicked")))
                        .and_then(|timing| {
                            if bytes.len() > MAX_OBJECT_BYTES {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "checkpoint reader exceeded the memory object limit",
                                ))
                            } else {
                                Ok(timing)
                            }
                        });
                        if ready_tx.send((worker, item, bytes, result)).is_err() {
                            break;
                        }
                    }
                });
            match handle {
                Ok(handle) => {
                    senders.push(work_tx);
                    handles.push(handle);
                }
                Err(error) => {
                    drop(senders);
                    drop(ready_rx);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(error);
                }
            }
        }
        drop(ready_tx);
        let result = (|| {
            let total = objects.len();
            let mut pending = objects.into_iter();
            for sender in &senders {
                let (id, item) = pending.next().expect("one initial item per reader");
                sender
                    .send((id, item, Vec::with_capacity(MAX_OBJECT_BYTES)))
                    .map_err(|_| io::Error::other("checkpoint reader stopped before reading"))?;
            }
            let mut timings = ObjectPipelineTiming::default();
            for _ in 0..total {
                let (worker, item, bytes, timing) = ready_rx
                    .recv()
                    .map_err(|_| io::Error::other("checkpoint reader stopped before completion"))?;
                let timing = timing?;
                timings.read_us += timing.read_us;
                timings.hash_us += timing.hash_us;
                timings.object_bytes += bytes.len() as u64;
                let consuming = Instant::now();
                consume(item, &bytes)?;
                timings.consume_us += consuming.elapsed().as_micros();
                if let Some((id, item)) = pending.next() {
                    senders[worker].send((id, item, bytes)).map_err(|_| {
                        io::Error::other("checkpoint reader stopped before its next object")
                    })?;
                }
            }
            timings.elapsed_us = started.elapsed().as_micros();
            Ok(timings)
        })();
        // Break both directions before joining: an errored consumer must not leave workers
        // blocked on a full completion queue or waiting for their next returned buffer.
        drop(senders);
        drop(ready_rx);
        let mut panicked = false;
        for handle in handles {
            panicked |= handle.join().is_err();
        }
        if panicked {
            return Err(io::Error::other("checkpoint object reader panicked"));
        }
        result
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn jobs(count: usize) -> Vec<(ObjectId, usize)> {
        (0..count)
            .map(|index| (ObjectId::from_bytes(&index.to_le_bytes()).unwrap(), index))
            .collect()
    }

    #[test]
    fn buffers_are_bounded_reused_and_consumed_on_the_caller_thread() {
        let pointers = Mutex::new(BTreeSet::new());
        let owner = std::thread::current().id();
        let mut observed = BTreeSet::new();
        let timings = run_pipeline(
            jobs(20),
            2,
            &|_, bytes| {
                pointers.lock().unwrap().insert(bytes.as_ptr() as usize);
                assert_eq!(bytes.capacity(), MAX_OBJECT_BYTES);
                bytes.resize(100, 7);
                Ok(CheckpointObjectReadTiming {
                    read_us: 2,
                    hash_us: 3,
                })
            },
            &mut |index, bytes| {
                assert_eq!(std::thread::current().id(), owner);
                assert_eq!(bytes, &[7; 100]);
                observed.insert(index);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(pointers.lock().unwrap().len(), 2);
        assert_eq!(observed.len(), 20);
        assert_eq!(timings.object_bytes, 2_000);
        assert_eq!((timings.read_us, timings.hash_us), (40, 60));
    }

    #[test]
    fn consumption_failure_joins_readers_and_does_not_start_remaining_jobs() {
        let reads = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let result = run_pipeline(
            jobs(20),
            2,
            &|_, _| {
                active.fetch_add(1, Ordering::SeqCst);
                reads.fetch_add(1, Ordering::SeqCst);
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(CheckpointObjectReadTiming::default())
            },
            &mut |_, _| Err(io::Error::other("injected guest write failure")),
        );
        assert!(result.is_err());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(reads.load(Ordering::SeqCst) <= 2);
    }

    #[test]
    fn unverified_bytes_never_reach_the_consumer() {
        let result = run_pipeline(
            jobs(1),
            1,
            &|_, bytes| {
                bytes.extend_from_slice(b"corrupt");
                Err(io::Error::new(io::ErrorKind::InvalidData, "bad digest"))
            },
            &mut |_, _| panic!("unverified object was consumed"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reader_panic_does_not_leave_other_readers_waiting_forever() {
        let result = run_pipeline(
            jobs(4),
            2,
            &|_, _| panic!("injected reader panic"),
            &mut |_, _| panic!("panicked reader was consumed"),
        );
        assert!(result.unwrap_err().to_string().contains("panicked"));
    }
}
