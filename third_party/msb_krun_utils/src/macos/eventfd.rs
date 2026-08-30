// Copyright 2021 Sergio Lopez. All rights reserved.
//
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Structure and wrapper functions emulating eventfd using a pipe.

use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{io, result};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::{dup, pipe, read, write};

pub const EFD_NONBLOCK: i32 = 1;

// NOTE: We introduce the semaphore flag here, but we don't implement the semantics exactly - We don't
//       return the correct value from read().
pub const EFD_SEMAPHORE: i32 = 2;

fn set_nonblock(fd: &OwnedFd) -> result::Result<(), io::Error> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits(flags).ok_or(io::ErrorKind::InvalidData)?;
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;

    Ok(())
}

#[derive(Debug)]
pub struct EventFd {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

impl EventFd {
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        let (read_fd, write_fd) = pipe()?;

        // Flags combine (`EFD_NONBLOCK | EFD_SEMAPHORE`); test the bit, not
        // the whole value, or a semaphore eventfd ends up blocking on read.
        if flag & EFD_NONBLOCK != 0 {
            set_nonblock(&read_fd)?;
            set_nonblock(&write_fd)?;
        }

        Ok(EventFd { read_fd, write_fd })
    }

    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        match write(&self.write_fd, &v.to_le_bytes()) {
            // We may get EAGAIN if the eventfd is overstimulated, but we can safely
            // ignore it as we can be sure the subscriber will get notified.
            Ok(_) | Err(Errno::EAGAIN) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn read(&self) -> result::Result<u64, io::Error> {
        let mut buf: [u8; 8] = [0; 8];
        read(&self.read_fd, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        let read_fd = dup(&self.read_fd)?;
        let write_fd = dup(&self.write_fd)?;
        Ok(EventFd { read_fd, write_fd })
    }

    pub fn get_write_fd(&self) -> RawFd {
        self.write_fd.as_raw_fd()
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        EventFd::new(EFD_NONBLOCK).unwrap();
        EventFd::new(0).unwrap();
    }

    #[test]
    fn test_read_write() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 55);
    }

    #[test]
    fn test_read_nothing() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let r = evt.read();
        match r {
            Err(ref inner) if inner.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("Unexpected"),
        }
    }
    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 923);
    }
}
