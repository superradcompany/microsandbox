//! Bounded ownership transfer from the paused RAM reader to immutable-object writers.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Instant;

use microsandbox_image::checkpoint::{
    CaptureObjectBatch, ContentRef, MemoryExtent, MemoryExtentContent, ObjectId,
};
use msb_krun::{GuestMemoryRange, MemoryCaptureSink};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const MEMORY_OBJECT_PACK_SIZE: usize = 32 * 1024 * 1024;
const WRITERS: usize = 2;
const BUFFER_COUNT: usize = WRITERS + 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct MemoryObjectSink {
    sender: Option<mpsc::SyncSender<Pack>>,
    completed: mpsc::Receiver<CompletedPack>,
    workers: Vec<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    pending: Pack,
    free: Vec<Vec<u8>>,
    updates: Vec<MemoryExtent>,
    in_flight: usize,
    stats: MemoryPipelineStats,
}

type PackWriter = dyn Fn(&[u8]) -> Result<ObjectId, String> + Send + Sync;

#[derive(Default)]
struct Pack {
    bytes: Vec<u8>,
    extents: Vec<(u64, u64, u64)>,
}

struct CompletedPack {
    pack: Pack,
    object: Result<ObjectId, String>,
    persist_us: u128,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MemoryPipelineStats {
    pub(super) wait_us: u128,
    pub(super) persist_us: u128,
    pub(super) packs: u64,
    pub(super) peak_in_flight_bytes: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MemoryObjectSink {
    pub(super) fn new(batch: Arc<CaptureObjectBatch>) -> io::Result<Self> {
        Self::with_writer(Arc::new(move |bytes| {
            batch.put_bytes(bytes).map_err(|error| error.to_string())
        }))
    }

    fn with_writer(write: Arc<PackWriter>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Pack>(WRITERS);
        let receiver = Arc::new(Mutex::new(receiver));
        let (completed_sender, completed) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut sink = Self {
            sender: Some(sender),
            completed,
            workers: Vec::with_capacity(WRITERS),
            cancelled,
            pending: Pack {
                bytes: Vec::with_capacity(MEMORY_OBJECT_PACK_SIZE),
                extents: Vec::new(),
            },
            free: (1..BUFFER_COUNT)
                .map(|_| Vec::with_capacity(MEMORY_OBJECT_PACK_SIZE))
                .collect(),
            updates: Vec::new(),
            in_flight: 0,
            stats: MemoryPipelineStats::default(),
        };
        for index in 0..WRITERS {
            let receiver = Arc::clone(&receiver);
            let completed_sender = completed_sender.clone();
            let cancelled = Arc::clone(&sink.cancelled);
            let write = Arc::clone(&write);
            let worker = std::thread::Builder::new()
                .name(format!("capture-pack-{index}"))
                .spawn(move || {
                    loop {
                        // The queue mutex protects receive only; never hold it during hashing or I/O.
                        let Ok(pack) = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv()
                        else {
                            break;
                        };
                        let started = Instant::now();
                        let object = if cancelled.load(Ordering::Acquire) {
                            Err("memory capture cancelled".to_string())
                        } else {
                            // Always return a buffer/completion even on a panicking storage worker,
                            // so the producer cannot wait forever for an in-flight pack.
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                write(&pack.bytes)
                            }))
                            .map_err(|_| "memory object writer panicked".to_string())
                            .and_then(|result| result)
                        };
                        if object.is_err() {
                            cancelled.store(true, Ordering::Release);
                        }
                        if completed_sender
                            .send(CompletedPack {
                                pack,
                                object,
                                persist_us: started.elapsed().as_micros(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })?;
            sink.workers.push(worker);
        }
        Ok(sink)
    }

    pub(super) fn finish(mut self) -> io::Result<(Vec<MemoryExtent>, MemoryPipelineStats)> {
        self.flush_pending()?;
        self.sender.take();
        while self.in_flight != 0 {
            self.receive()?;
        }
        self.join()?;
        Ok((std::mem::take(&mut self.updates), self.stats))
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending.bytes.is_empty() {
            return Ok(());
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::other("memory object writer failed"));
        }
        // No borrowed guest-memory slice leaves write_bytes. At most three owned packs exist,
        // including this producer's pack; a slow disk applies backpressure instead of allocating.
        let pack = std::mem::take(&mut self.pending);
        let started = Instant::now();
        self.sender
            .as_ref()
            .expect("capture is open")
            .send(pack)
            .map_err(|_| io::Error::other("memory object writers disconnected"))?;
        self.stats.wait_us += started.elapsed().as_micros();
        self.in_flight += 1;
        self.stats.packs += 1;
        self.stats.peak_in_flight_bytes = self
            .stats
            .peak_in_flight_bytes
            .max(self.in_flight * MEMORY_OBJECT_PACK_SIZE);
        while self.free.is_empty() {
            self.receive()?;
        }
        self.pending.bytes = self.free.pop().expect("received reusable buffer");
        Ok(())
    }

    fn receive(&mut self) -> io::Result<()> {
        let started = Instant::now();
        let completed = self
            .completed
            .recv()
            .map_err(|_| io::Error::other("memory object writers disconnected"))?;
        self.stats.wait_us += started.elapsed().as_micros();
        self.in_flight -= 1;
        self.stats.persist_us += completed.persist_us;
        let object = completed.object.map_err(io::Error::other)?;
        let mut pack = completed.pack;
        self.updates.extend(
            pack.extents
                .drain(..)
                .map(|(start, length, object_offset)| MemoryExtent {
                    start,
                    length,
                    content: MemoryExtentContent::Object(ContentRef {
                        object: object.clone(),
                        object_offset,
                    }),
                }),
        );
        pack.bytes.clear();
        self.free.push(pack.bytes);
        Ok(())
    }

    fn join(&mut self) -> io::Result<()> {
        let mut failed = false;
        for worker in self.workers.drain(..) {
            failed |= worker.join().is_err();
        }
        if failed {
            return Err(io::Error::other("memory object writer panicked"));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for MemoryObjectSink {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.sender.take();
        // Finish/drop cannot let a writer recreate staging files after failure cleanup starts.
        let _ = self.join();
    }
}

impl MemoryCaptureSink for MemoryObjectSink {
    fn write_bytes(&mut self, range: GuestMemoryRange, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 != range.length() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory sink range length does not match bytes",
            ));
        }
        // libkrun currently supplies <=2MiB ranges. Splitting also keeps the bound valid if a
        // future caller supplies a larger range, without changing that range's guest projection.
        let mut consumed = 0;
        while consumed < bytes.len() {
            if self.pending.bytes.len() == MEMORY_OBJECT_PACK_SIZE {
                self.flush_pending()?;
            }
            let count =
                (MEMORY_OBJECT_PACK_SIZE - self.pending.bytes.len()).min(bytes.len() - consumed);
            let offset = self.pending.bytes.len() as u64;
            self.pending
                .bytes
                .extend_from_slice(&bytes[consumed..consumed + count]);
            self.pending
                .extents
                .push((range.start() + consumed as u64, count as u64, offset));
            consumed += count;
        }
        Ok(())
    }

    fn write_zero(&mut self, range: GuestMemoryRange) -> io::Result<()> {
        self.updates.push(MemoryExtent {
            start: range.start(),
            length: range.length(),
            content: MemoryExtentContent::Zero,
        });
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::LocalObjectStore;

    #[test]
    fn sparse_ranges_keep_exact_object_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let batch = Arc::new(CaptureObjectBatch::new(store.clone(), &[]));
        let mut sink = MemoryObjectSink::new(Arc::clone(&batch)).unwrap();
        sink.write_bytes(GuestMemoryRange::new(4096, 3).unwrap(), b"abc")
            .unwrap();
        sink.write_zero(GuestMemoryRange::new(8192, 4).unwrap())
            .unwrap();
        sink.write_bytes(GuestMemoryRange::new(12288, 2).unwrap(), b"de")
            .unwrap();
        let (mut extents, stats) = sink.finish().unwrap();
        batch.finish().unwrap();
        extents.sort_by_key(|extent| extent.start);
        assert_eq!(stats.packs, 1);
        assert!(matches!(extents[1].content, MemoryExtentContent::Zero));
        let MemoryExtentContent::Object(first) = &extents[0].content else {
            panic!()
        };
        let MemoryExtentContent::Object(last) = &extents[2].content else {
            panic!()
        };
        assert_eq!(first.object, last.object);
        assert_eq!(last.object_offset, 3);
        assert_eq!(
            std::fs::read(store.object_path(&first.object)).unwrap(),
            b"abcde"
        );
    }

    #[test]
    fn oversized_input_remains_bounded_and_storage_failure_joins_workers() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(dir.path()).unwrap();
        let batch = Arc::new(CaptureObjectBatch::new(store, &[]));
        let mut sink = MemoryObjectSink::new(Arc::clone(&batch)).unwrap();
        let bytes = vec![7; MEMORY_OBJECT_PACK_SIZE * 4 + 1];
        sink.write_bytes(
            GuestMemoryRange::new(0, bytes.len() as u64).unwrap(),
            &bytes,
        )
        .unwrap();
        let (extents, stats) = sink.finish().unwrap();
        assert_eq!(stats.packs, 5);
        assert_eq!(
            extents.iter().map(|extent| extent.length).sum::<u64>(),
            bytes.len() as u64
        );
        assert!(stats.peak_in_flight_bytes <= BUFFER_COUNT * MEMORY_OBJECT_PACK_SIZE);

        let bad = LocalObjectStore::open(dir.path().join("bad")).unwrap();
        std::fs::remove_dir_all(dir.path().join("bad/objects")).unwrap();
        std::fs::write(dir.path().join("bad/objects"), b"not a directory").unwrap();
        let batch = Arc::new(CaptureObjectBatch::new(bad, &[]));
        let mut sink = MemoryObjectSink::new(Arc::clone(&batch)).unwrap();
        sink.write_bytes(GuestMemoryRange::new(0, 1).unwrap(), b"x")
            .unwrap();
        assert!(sink.finish().is_err());
        assert_eq!(
            Arc::strong_count(&batch),
            1,
            "all writer references must be joined"
        );
    }

    #[test]
    fn panicking_writer_returns_an_error_instead_of_stranding_a_pack() {
        let mut sink =
            MemoryObjectSink::with_writer(Arc::new(|_| panic!("injected pack writer panic")))
                .unwrap();
        sink.write_bytes(GuestMemoryRange::new(0, 1).unwrap(), b"x")
            .unwrap();
        assert!(sink.finish().unwrap_err().to_string().contains("panicked"));
    }

    #[test]
    fn dropping_capture_waits_until_active_writes_have_finished() {
        use std::sync::atomic::AtomicUsize;
        let active = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (started_sender, started) = mpsc::channel();
        let writer_active = Arc::clone(&active);
        let writer_barrier = Arc::clone(&barrier);
        let mut sink = MemoryObjectSink::with_writer(Arc::new(move |bytes| {
            writer_active.fetch_add(1, Ordering::SeqCst);
            started_sender.send(()).unwrap();
            writer_barrier.wait();
            let id = ObjectId::from_bytes(bytes).map_err(|error| error.to_string());
            writer_active.fetch_sub(1, Ordering::SeqCst);
            id
        }))
        .unwrap();
        sink.write_bytes(GuestMemoryRange::new(0, 1).unwrap(), b"x")
            .unwrap();
        sink.flush_pending().unwrap();
        started.recv().unwrap();
        let cancelled = Arc::clone(&sink.cancelled);
        let dropping = std::thread::spawn(move || drop(sink));
        while !cancelled.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert_eq!(active.load(Ordering::SeqCst), 1);
        barrier.wait();
        dropping.join().unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn out_of_order_writers_preserve_each_packs_guest_projection() {
        let (release_first, wait_first) = mpsc::channel();
        let wait_first = Mutex::new(wait_first);
        let mut sink = MemoryObjectSink::with_writer(Arc::new(move |bytes| {
            if bytes == b"a" {
                wait_first.lock().unwrap().recv().unwrap();
            }
            ObjectId::from_bytes(bytes).map_err(|error| error.to_string())
        }))
        .unwrap();
        sink.write_bytes(GuestMemoryRange::new(4096, 1).unwrap(), b"a")
            .unwrap();
        sink.flush_pending().unwrap();
        sink.write_bytes(GuestMemoryRange::new(8192, 1).unwrap(), b"b")
            .unwrap();
        sink.flush_pending().unwrap();
        sink.receive().unwrap();
        assert_eq!(
            sink.updates[0].start, 8192,
            "the later pack must finish first in this test"
        );
        release_first.send(()).unwrap();
        let (extents, _) = sink.finish().unwrap();
        assert_eq!(
            extents
                .iter()
                .map(|extent| extent.start)
                .collect::<Vec<_>>(),
            vec![8192, 4096]
        );
        for (extent, bytes) in extents.iter().zip([b"b", b"a"]) {
            let MemoryExtentContent::Object(content) = &extent.content else {
                panic!()
            };
            assert_eq!(content.object, ObjectId::from_bytes(bytes).unwrap());
            assert_eq!(content.object_offset, 0);
        }
        // The coordinator's overlay_extents sorts and validates these projections before any
        // canonical manifest is encoded. Worker completion ordering is never artifact ordering.
    }
}
