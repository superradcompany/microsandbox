use crate::eventfd::{EventFd, EFD_NONBLOCK, EFD_SEMAPHORE};
use std::collections::VecDeque;
use std::io;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Arc, Mutex};

/// A multiple producer single consumer channel that can be listened to by a file descriptor
pub fn pollable_channel<T: Send>(
) -> io::Result<(PollableChannelSender<T>, PollableChannelReciever<T>)> {
    let eventfd = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE)?;

    let inner = Arc::new(Inner {
        eventfd,
        queue: Mutex::new(VecDeque::new()),
    });
    let tx = PollableChannelSender {
        inner: inner.clone(),
    };
    let rx = PollableChannelReciever { inner };
    Ok((tx, rx))
}

struct Inner<T: Send> {
    eventfd: EventFd,
    queue: Mutex<VecDeque<T>>,
}

#[derive(Clone)]
pub struct PollableChannelSender<T: Send> {
    inner: Arc<Inner<T>>,
}

impl<T: Send> PollableChannelSender<T> {
    pub fn send(&self, msg: T) -> io::Result<()> {
        let mut data_lock = self.inner.queue.lock().unwrap();
        data_lock.push_back(msg);
        self.inner.eventfd.write(1)?;
        Ok(())
    }

    pub fn send_many<I: IntoIterator<Item = T>>(&self, msg_iterator: I) -> io::Result<()> {
        let msg_iterator = msg_iterator.into_iter();
        let mut data_lock = self.inner.queue.lock().unwrap();
        let old_len = data_lock.len();
        data_lock.extend(msg_iterator);
        let num_added_items = data_lock.len() - old_len;
        self.inner.eventfd.write(num_added_items as u64)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PollableChannelReciever<T: Send> {
    inner: Arc<Inner<T>>,
}

impl<T: Send> PollableChannelReciever<T> {
    pub fn try_recv(&self) -> io::Result<Option<T>> {
        let mut data_lock = self.inner.queue.lock().unwrap();
        match self.inner.eventfd.read() {
            Ok(_) => (),
            Err(e) if e.kind() == ErrorKind::WouldBlock => (),
            Err(e) => return Err(e),
        }

        Ok(data_lock.pop_front())
    }

    pub fn len(&self) -> usize {
        self.inner.queue.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.queue.lock().unwrap().is_empty()
    }
}

#[cfg(unix)]
impl<T: Send> AsRawFd for PollableChannelReciever<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.eventfd.as_raw_fd()
    }
}

#[cfg(unix)]
impl<T: Send> AsFd for PollableChannelReciever<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: The lifetime of the fd is the same as the lifetime of self.inner.eventfd which
        //         is the same as the lifetime of self.
        unsafe { BorrowedFd::borrow_raw(self.inner.eventfd.as_raw_fd()) }
    }
}

#[cfg(windows)]
impl<T: Send> AsRawHandle for PollableChannelReciever<T> {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.eventfd.as_raw_handle()
    }
}
