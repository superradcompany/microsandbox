use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use super::super::Queue as VirtQueue;
use super::defs::uapi;
use super::packet::VsockPacket;

use crate::virtio::InterruptTransport;
use vm_memory::GuestMemoryMmap;

const UPDATE_INTERVAL: u64 = 60 * 1000 * 1000 * 1000;
const SLEEP_NSECS: u64 = 2 * 1000 * 1000 * 1000;
const TSYNC_PORT: u32 = 123;

pub struct TimesyncThread {
    cid: u64,
    mem: GuestMemoryMmap,
    queue_mutex: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
}

impl TimesyncThread {
    pub fn new(
        cid: u64,
        mem: GuestMemoryMmap,
        queue_mutex: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
    ) -> Self {
        Self {
            cid,
            mem,
            queue_mutex,
            interrupt,
        }
    }

    fn send_time(&self, time: u64) {
        let mut queue = self.queue_mutex.lock().unwrap();
        if let Some(head) = queue.pop(&self.mem) {
            if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                pkt.set_op(uapi::VSOCK_OP_RW)
                    .set_src_cid(uapi::VSOCK_HOST_CID)
                    .set_dst_cid(self.cid)
                    .set_src_port(TSYNC_PORT)
                    .set_dst_port(TSYNC_PORT)
                    .set_type(uapi::VSOCK_TYPE_DGRAM);

                pkt.write_time_sync(time);
                pkt.set_len(pkt.buf().unwrap().len() as u32);
                if let Err(e) =
                    queue.add_used(&self.mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {e:?}");
                }
                self.interrupt.signal_used_queue();
            }
        }
    }

    fn work(&mut self) {
        let mut last_update = 0u64;
        let mut last_awake = utils::time::get_time(utils::time::ClockType::Real);
        loop {
            let now = utils::time::get_time(utils::time::ClockType::Real);
            /*
             * We send a time sync packet if we slept for 3 times more
             * nanoseconds than expected (which is an indication the
             * system forced us to take a long nap), or if UPDATE_INTERVAL
             * has been reached.
             */
            if (now - last_awake) >= (SLEEP_NSECS * 3) || (now - last_update) >= UPDATE_INTERVAL {
                self.send_time(now);
                last_update = now;
            }

            last_awake = utils::time::get_time(utils::time::ClockType::Real);
            thread::sleep(time::Duration::from_nanos(SLEEP_NSECS));
        }
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("vsock timesync".into())
            .spawn(move || self.work())
            .unwrap();
    }
}
