//! Guest-side Ethernet device shared by network boundary tests.

use msb_krun::backends::net::{NetBackend, ReadError};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct GuestDevice(pub(super) Box<dyn NetBackend + Send>);

pub(super) struct GuestRx(Vec<u8>);

pub(super) struct GuestTx<'a>(&'a mut GuestDevice);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Device for GuestDevice {
    type RxToken<'a> = GuestRx;
    type TxToken<'a> = GuestTx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(GuestRx, GuestTx<'_>)> {
        let mut frame = vec![0; 2048];
        match self.0.read_frame(&mut frame) {
            Ok(len) => Some((GuestRx(frame[12..len].to_vec()), GuestTx(self))),
            Err(ReadError::NothingRead) => None,
            Err(error) => panic!("reading guest frame: {error:?}"),
        }
    }

    fn transmit(&mut self, _: Instant) -> Option<GuestTx<'_>> {
        Some(GuestTx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1514;
        capabilities
    }
}

impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; 12 + len];
        let result = f(&mut frame[12..]);
        self.0.0.write_frame(12, &mut frame).unwrap();
        result
    }
}
//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn ipv6_loopback_unavailable(error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT) => true,
        // Winsock WSAEPROTONOSUPPORT / WSAEAFNOSUPPORT. Keep this test-only check
        // independent of the optional windows-sys WinSock feature.
        #[cfg(windows)]
        Some(10043 | 10047) => true,
        _ => error.kind() == std::io::ErrorKind::AddrNotAvailable,
    }
}
