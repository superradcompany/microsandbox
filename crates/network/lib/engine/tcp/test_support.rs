//! Packet-level fixtures for relay shutdown tests.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as StackInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::time::{Duration, Instant, advance};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct TestNetwork {
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    guest: SocketHandle,
    device: Loopback,
    started: Instant,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TestNetwork {
    pub(crate) fn new(guest_connects: bool) -> Self {
        let mut device = Loopback::new(Medium::Ethernet);
        let mac = EthernetAddress([2, 0, 0, 0, 0, 1]);
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(mac)),
            &mut device,
            StackInstant::from_millis(0),
        );

        // Put the dialing endpoint first so ARP uses its source address.
        let addresses = if guest_connects { [1, 2] } else { [2, 1] };
        iface.update_ip_addrs(|ips| {
            for last in addresses {
                ips.push(IpCidr::new(IpAddress::v4(10, 0, 0, last), 24))
                    .unwrap();
            }
        });

        let mut guest = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 16384]),
            tcp::SocketBuffer::new(vec![0; 16384]),
        );
        if guest_connects {
            guest
                .connect(
                    iface.context(),
                    (IpAddress::v4(10, 0, 0, 2), 8099),
                    (IpAddress::v4(10, 0, 0, 1), 12345),
                )
                .unwrap();
        } else {
            guest.listen((IpAddress::v4(10, 0, 0, 1), 12345)).unwrap();
        }

        let mut sockets = SocketSet::new(vec![]);
        let guest = sockets.add(guest);

        Self {
            iface,
            sockets,
            guest,
            device,
            started: Instant::now(),
        }
    }

    pub(crate) fn poll(&mut self) {
        let now = StackInstant::from_millis(self.started.elapsed().as_millis() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    pub(crate) fn guest_state(&self) -> tcp::State {
        self.sockets.get::<tcp::Socket>(self.guest).state()
    }

    /// Exercise actual TCP flow control, payload delivery, FIN, and timeout RST.
    pub(crate) async fn check_drain(
        &mut self,
        mut relay: impl FnMut(&mut SocketSet<'_>),
        payload: &[u8],
        stalled: bool,
    ) {
        // Many polls without advancing time must never exhaust a close budget.
        // The small receive window fills while the guest is not reading.
        for _ in 0..256 {
            relay(&mut self.sockets);
            self.poll();
            assert_eq!(self.guest_state(), tcp::State::Established);
        }

        if stalled {
            advance(Duration::from_secs(29)).await;
            relay(&mut self.sockets);
            self.poll();
            assert_eq!(self.guest_state(), tcp::State::Established);

            advance(Duration::from_secs(1)).await;
            relay(&mut self.sockets);
            // One pass emits the RST and another delivers it to the peer.
            for _ in 0..4 {
                self.poll();
            }
            assert_eq!(self.guest_state(), tcp::State::Closed);
            return;
        }

        let mut received = Vec::new();
        let mut chunk = [0; 4096];

        // Drain for longer than the idle timeout, making progress every two seconds.
        for _ in 0..128 {
            let guest = self.sockets.get_mut::<tcp::Socket>(self.guest);
            assert_ne!(guest.state(), tcp::State::Closed, "unexpected reset");
            if guest.can_recv() {
                let n = guest.recv_slice(&mut chunk).unwrap();
                received.extend_from_slice(&chunk[..n]);
            }
            if guest.state() == tcp::State::CloseWait && !guest.can_recv() {
                assert_eq!(received, payload);
                assert!(self.started.elapsed() > Duration::from_secs(30));
                return;
            }

            advance(Duration::from_secs(2)).await;
            for _ in 0..16 {
                self.poll();
                relay(&mut self.sockets);
            }
        }

        panic!("response did not finish with EOF");
    }
}
