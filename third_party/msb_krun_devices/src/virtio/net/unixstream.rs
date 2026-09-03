use nix::sys::socket::{
    connect, getsockopt, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use std::{
    os::fd::{AsRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use crate::virtio::net::backend::ConnectError;

use super::backend::{NetBackend, ReadError, WriteError};
use super::write_virtio_net_hdr;

/// Each frame the network proxy is prepended by a 4 byte "header".
/// It is interpreted as a big-endian u32 integer and is the length of the following ethernet frame.
const FRAME_HEADER_LEN: usize = 4;

pub struct Unixstream {
    fd: OwnedFd,
    // 0 when a frame length has not been read
    expecting_frame_length: u32,
    // 0 if last write is fully complete, otherwise the length that was written
    last_partial_write_length: usize,
}

impl Unixstream {
    /// Create the backend with a pre-established connection to the userspace network proxy.
    pub fn new(fd: OwnedFd) -> Self {
        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network proxy socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Self {
            fd,
            expecting_frame_length: 0,
            last_partial_write_length: 0,
        }
    }

    /// Create the backend opening a connection to the userspace network proxy.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(ConnectError::CreateSocket)?;
        let peer_addr = UnixAddr::new(&path).map_err(ConnectError::InvalidAddress)?;
        connect(fd.as_raw_fd(), &peer_addr).map_err(ConnectError::Binding)?;

        if let Err(e) = setsockopt(&fd, sockopt::SndBuf, &(16 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "network socket (fd {fd:?}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            getsockopt(&fd, sockopt::SndBuf),
            getsockopt(&fd, sockopt::RcvBuf)
        );

        Ok(Self {
            fd,
            expecting_frame_length: 0,
            last_partial_write_length: 0,
        })
    }

    /// Try to read until filling the whole slice.
    fn read_loop(&self, buf: &mut [u8], block_until_has_data: bool) -> Result<(), ReadError> {
        let mut bytes_read = 0;
        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        if !block_until_has_data {
            match recv(self.fd.as_raw_fd(), buf, flags) {
                Ok(size) => bytes_read += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    return Err(ReadError::NothingRead)
                }
                Err(e) => return Err(ReadError::Internal(e)),
            }
        }

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_WAITALL | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_WAITALL;

        while bytes_read < buf.len() {
            match recv(self.fd.as_raw_fd(), &mut buf[bytes_read..], flags) {
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    log::warn!("read_loop: unexpected EAGAIN/EWOULDBLOCK on blocking socket");
                    continue;
                }
                Err(e) => return Err(ReadError::Internal(e)),
                Ok(size) => {
                    bytes_read += size;
                    //log::trace!("proxy recv {}/{}", bytes_read, buf.len());
                }
            }
        }

        Ok(())
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_send = 0;

        #[cfg(target_os = "linux")]
        let flags = MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        let flags = MsgFlags::MSG_DONTWAIT;

        while bytes_send < buf.len() {
            match send(self.fd.as_raw_fd(), &buf[bytes_send..], flags) {
                Ok(size) => bytes_send += size,
                #[allow(unreachable_patterns)]
                Err(nix::Error::EAGAIN | nix::Error::EWOULDBLOCK) => {
                    if bytes_send == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        log::trace!(
                            "Wrote {bytes_send} bytes, but socket blocked, will need try_finish_write() to finish"
                        );

                        self.last_partial_write_length += bytes_send;
                        return Err(WriteError::PartialWrite);
                    }
                }
                Err(nix::Error::EPIPE) => return Err(WriteError::ProcessNotRunning),
                Err(e) => return Err(WriteError::Internal(e)),
            }
        }
        self.last_partial_write_length = 0;
        Ok(())
    }
}

impl NetBackend for Unixstream {
    /// Try to read a frame from the proxy. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; FRAME_HEADER_LEN];
                self.read_loop(&mut frame_length_buf, false)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }

        let hdr_len = write_virtio_net_hdr(buf);
        let buf = &mut buf[hdr_len..];
        let frame_length = self.expecting_frame_length as usize;
        self.read_loop(&mut buf[..frame_length], false)?;
        self.expecting_frame_length = 0;
        log::trace!("Read eth frame from network proxy: {frame_length} bytes");
        Ok(hdr_len + frame_length)
    }

    /// Try to write a frame to the proxy.
    /// (Will mutate and override parts of buf, with a frame header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= FRAME_HEADER_LEN.
    /// * `buf` - the buffer to write to the proxy, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame to the proxy, while a partial write is not resolved.");
        }
        assert!(
            hdr_len >= FRAME_HEADER_LEN,
            "Not enough space to write the frame header"
        );
        assert!(buf.len() > hdr_len);
        let frame_length = buf.len() - hdr_len;

        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])?;
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    /// Try to finish a partial write
    ///
    /// If no partial write is required will do nothing and return Ok(())
    ///
    /// * `hdr_len` - must be the same value as passed to write_frame, that caused the partial write
    /// * `buf` - must be same buffer that was given to write_frame, that caused the partial write
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            log::trace!("Requested to finish partial write");
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
            log::debug!("Finished partial write ({already_written}bytes written before)")
        }

        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
