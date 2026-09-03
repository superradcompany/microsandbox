use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use super::proxy::Proxy;
use crossbeam_channel::Receiver;

pub type ProxyMap = Arc<RwLock<HashMap<u64, Mutex<Box<dyn Proxy>>>>>;
const TIMEOUT: Duration = Duration::new(5, 0);

pub struct ReaperThread {
    receiver: Receiver<u64>,
    proxy_map: ProxyMap,
    released_map: HashMap<u64, Instant>,
}

impl ReaperThread {
    pub fn new(receiver: Receiver<u64>, proxy_map: ProxyMap) -> Self {
        Self {
            receiver,
            proxy_map,
            released_map: HashMap::new(),
        }
    }

    fn check_expiration(&mut self) -> Duration {
        let mut highest_elapsed = Duration::ZERO;
        let mut expired: Vec<u64> = Vec::new();
        let now = Instant::now();

        for (id, exptime) in self.released_map.iter() {
            let elapsed = now.duration_since(*exptime);
            if elapsed >= TIMEOUT {
                expired.push(*id);
            } else if elapsed > highest_elapsed {
                highest_elapsed = elapsed;
            }
        }

        if !expired.is_empty() {
            let mut pmap = self.proxy_map.write().unwrap();
            for id in expired {
                debug!("removing proxy: {id}");
                pmap.remove(&id);
                self.released_map.remove(&id);
            }
            debug!("remainig proxies: {}", pmap.len());
        }

        let mut timeout = Duration::MAX;
        if highest_elapsed > Duration::ZERO {
            timeout = TIMEOUT - highest_elapsed;
            assert!(timeout > Duration::ZERO);
        }
        timeout
    }

    fn work(&mut self) {
        loop {
            let timeout = self.check_expiration();
            if let Ok(id) = self.receiver.recv_timeout(timeout) {
                self.released_map.insert(id, Instant::now());
            }
        }
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("vsock reaper".into())
            .spawn(move || self.work())
            .unwrap();
    }
}
