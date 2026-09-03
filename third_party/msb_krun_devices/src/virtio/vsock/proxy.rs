#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::fmt;
#[cfg(unix)]
use std::os::fd::OwnedFd;

use super::muxer::MuxerRx;
#[cfg(windows)]
use super::packet::VsockPacket;
#[cfg(unix)]
use super::packet::{TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket};
use super::VsockPollable;
#[cfg(unix)]
use nix::sys::socket::AddressFamily;
use utils::epoll::EventSet;

#[derive(Debug)]
pub enum RecvPkt {
    Close,
    Error,
    Read(usize),
    WaitForCredit,
}

#[cfg(unix)]
#[allow(dead_code)]
#[derive(Debug)]
pub enum ProxyError {
    CreatingSocket(nix::errno::Errno),
    InvalidFamily,
    SettingReuseAddr(nix::errno::Errno),
    SettingReusePort(nix::errno::Errno),
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum ProxyStatus {
    #[cfg(unix)]
    Idle,
    Connecting,
    Connected,
    #[cfg(unix)]
    Listening,
    Closed,
    WaitingCreditUpdate,
    #[cfg(unix)]
    ReverseInit,
    #[cfg(unix)]
    WaitingOnAccept,
}

#[derive(Default)]
pub enum ProxyRemoval {
    #[default]
    Keep,
    Immediate,
    Deferred,
}

#[cfg(unix)]
#[derive(Default)]
pub enum NewProxyType {
    #[default]
    Tcp,
    Unix,
}

#[derive(Default)]
pub struct ProxyUpdate {
    pub signal_queue: bool,
    pub remove_proxy: ProxyRemoval,
    pub polling: Option<(u64, VsockPollable, EventSet)>,
    #[cfg(unix)]
    pub new_proxy: Option<(u32, OwnedFd, AddressFamily, NewProxyType)>,
    #[cfg(unix)]
    pub push_accept: Option<(u64, u64)>,
    pub push_credit_req: Option<MuxerRx>,
}

#[cfg(unix)]
impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub trait Proxy: Send {
    #[cfg(unix)]
    fn id(&self) -> u64;
    fn pollable(&self) -> VsockPollable;
    #[allow(dead_code)]
    fn status(&self) -> ProxyStatus;
    #[cfg(unix)]
    fn connect(&mut self, pkt: &VsockPacket, req: TsiConnectReq) -> ProxyUpdate;
    fn confirm_connect(&mut self, _pkt: &VsockPacket) -> Option<ProxyUpdate> {
        None
    }
    #[cfg(unix)]
    fn getpeername(&mut self, pkt: &VsockPacket);
    fn sendmsg(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    #[cfg(unix)]
    fn sendto_addr(&mut self, req: TsiSendtoAddr) -> ProxyUpdate;
    #[cfg(unix)]
    fn sendto_data(&mut self, _pkt: &VsockPacket) {}
    #[cfg(unix)]
    fn listen(
        &mut self,
        pkt: &VsockPacket,
        req: TsiListenReq,
        host_port_map: &Option<HashMap<u16, u16>>,
    ) -> ProxyUpdate;
    #[cfg(unix)]
    fn accept(&mut self, req: TsiAcceptReq) -> ProxyUpdate;
    fn update_peer_credit(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    #[cfg(unix)]
    fn push_op_request(&self) {}
    fn process_op_response(&mut self, pkt: &VsockPacket) -> ProxyUpdate;
    #[cfg(unix)]
    fn enqueue_accept(&mut self) {}
    #[cfg(unix)]
    fn push_accept_rsp(&self, _result: i32) {}
    fn shutdown(&mut self, _pkt: &VsockPacket) {}
    fn release(&mut self) -> ProxyUpdate;
    fn process_event(&mut self, evset: EventSet) -> ProxyUpdate;
    /// Retry backend work after the guest makes receive capacity available.
    fn kick(&self) {}
}
