//! Bound stdin before transport admission so output credits cannot be trapped behind input.

use std::sync::{Arc, Mutex};

use microsandbox_protocol::exec::EXEC_STDIN_WINDOW;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct InputWindow {
    available: Semaphore,
    offsets: Mutex<Offsets>,
}

pub(super) struct InputReservation<'a> {
    window: &'a InputWindow,
    permit: Option<SemaphorePermit<'a>>,
    bytes: u32,
}

#[derive(Default)]
struct Offsets {
    sent: u64,
    consumed: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InputWindow {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            available: Semaphore::new(EXEC_STDIN_WINDOW as usize),
            offsets: Mutex::new(Offsets::default()),
        })
    }

    pub(super) async fn reserve(&self, bytes: u32) -> MicrosandboxResult<InputReservation<'_>> {
        let permit = self
            .available
            .acquire_many(bytes)
            .await
            .map_err(|_| MicrosandboxError::Runtime("execution stdin closed".into()))?;
        let mut offsets = self.offsets.lock().unwrap();
        offsets.sent = offsets
            .sent
            .checked_add(u64::from(bytes))
            .ok_or_else(|| MicrosandboxError::Runtime("execution stdin offset overflow".into()))?;
        Ok(InputReservation {
            window: self,
            permit: Some(permit),
            bytes,
        })
    }

    pub(super) fn acknowledge(&self, consumed: u64) -> bool {
        let mut offsets = self.offsets.lock().unwrap();
        if consumed < offsets.consumed || consumed > offsets.sent {
            return false;
        }
        self.available
            .add_permits((consumed - offsets.consumed) as usize);
        offsets.consumed = consumed;
        true
    }

    pub(super) fn close(&self) {
        self.available.close();
    }
}

impl InputReservation<'_> {
    pub(super) fn commit(mut self) {
        self.permit.take().unwrap().forget();
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for InputReservation<'_> {
    fn drop(&mut self) {
        if self.permit.is_some() {
            self.window.offsets.lock().unwrap().sent -= u64::from(self.bytes);
        }
    }
}
