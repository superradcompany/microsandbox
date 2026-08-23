//! Windows system DNS resolution through the Windows DNS Client.
//!
//! Host-default queries must follow the Windows DNS Client rather than flattening every adapter's
//! configured servers into one list. The system client owns NRPT, VPN and split-DNS selection,
//! encrypted DNS, resolver health, caching, and interface routing. New Windows builds use
//! `DnsQueryRaw`; older builds fall back to `DnsQueryEx` through the compatibility module.

mod compatibility;

use std::ffi::c_void;
use std::io::{self, Error, ErrorKind};
use std::mem;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{DNS_REQUEST_PENDING, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_PROTOCOL_TCP, DNS_PROTOCOL_UDP, DNS_QUERY_RAW_CANCEL, DNS_QUERY_RAW_REQUEST,
    DNS_QUERY_RAW_REQUEST_VERSION1, DNS_QUERY_RAW_RESULT, DNS_QUERY_RAW_RESULTS_VERSION1,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

use super::common::transport::Transport;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DNSAPI_DLL: &[u16] = &[
    b'd' as u16,
    b'n' as u16,
    b's' as u16,
    b'a' as u16,
    b'p' as u16,
    b'i' as u16,
    b'.' as u16,
    b'd' as u16,
    b'l' as u16,
    b'l' as u16,
    0,
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type DnsQueryRawFn =
    unsafe extern "system" fn(*const DNS_QUERY_RAW_REQUEST, *mut DNS_QUERY_RAW_CANCEL) -> i32;
type DnsCancelQueryRawFn = unsafe extern "system" fn(*const DNS_QUERY_RAW_CANCEL) -> i32;
type DnsQueryRawResultFreeFn = unsafe extern "system" fn(*const DNS_QUERY_RAW_RESULT);

#[derive(Clone, Copy)]
struct RawDnsApi {
    query: DnsQueryRawFn,
    cancel: DnsCancelQueryRawFn,
    free_result: DnsQueryRawResultFreeFn,
}

/// Resolver for host-default DNS queries on Windows.
pub(crate) struct WindowsSystemResolver {
    query_timeout: Duration,
    raw_api: Option<RawDnsApi>,
}

/// Stable state shared by the waiting future and the Windows completion callback.
struct QueryState {
    sender: Mutex<Option<oneshot::Sender<io::Result<Vec<u8>>>>>,
    cancel: Mutex<DNS_QUERY_RAW_CANCEL>,
    api: RawDnsApi,
}

/// Cancels an in-flight Windows query when its future is timed out or dropped.
struct PendingQuery {
    state: Arc<QueryState>,
    completed: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsSystemResolver {
    pub(crate) fn new(query_timeout: Duration) -> Self {
        Self {
            query_timeout,
            raw_api: raw_dns_api(),
        }
    }

    /// Resolve one guest wire-format query through the Windows DNS Client.
    pub(crate) async fn query(
        &self,
        raw_query: &[u8],
        transport: Transport,
    ) -> io::Result<Vec<u8>> {
        if self.raw_api.is_none() {
            return compatibility::query(raw_query, transport, self.query_timeout).await;
        }

        // Launch synchronously so the pointer-bearing Windows request does not live across an
        // `.await`; only the cancellation handle and Send channel receiver enter the future state.
        let (mut pending, receiver) = start_query(self.raw_api.unwrap(), raw_query, transport)?;
        let result = tokio::time::timeout(self.query_timeout, receiver)
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "Windows system DNS query timed out"))?
            .map_err(|_| Error::other("Windows system DNS callback was dropped"))??;
        pending.completed = true;

        finish_response(result, transport)
    }
}

impl Drop for PendingQuery {
    fn drop(&mut self) {
        if !self.completed {
            // The callback owns another Arc, so the stable cancel handle remains allocated even if
            // DnsCancelQueryRaw returns before Windows invokes the cancellation callback.
            let cancel = self
                .state
                .cancel
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            unsafe {
                let _ = (self.state.api.cancel)(&*cancel);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn raw_dns_api() -> Option<RawDnsApi> {
    static API: OnceLock<Option<RawDnsApi>> = OnceLock::new();
    *API.get_or_init(load_raw_dns_api)
}

fn load_raw_dns_api() -> Option<RawDnsApi> {
    // DnsQueryEx statically loads dnsapi.dll. Runtime lookup keeps newer raw-query symbols out of
    // the PE import table, allowing the same executable to start when those exports are absent.
    // SAFETY: DNSAPI_DLL is a static, NUL-terminated UTF-16 string.
    let module = unsafe { GetModuleHandleW(DNSAPI_DLL.as_ptr()) };
    if module.is_null() {
        return None;
    }

    // SAFETY: each non-null export is cast to its documented windns.h function signature.
    unsafe {
        let query = GetProcAddress(module, c"DnsQueryRaw".as_ptr().cast())?;
        let cancel = GetProcAddress(module, c"DnsCancelQueryRaw".as_ptr().cast())?;
        let free_result = GetProcAddress(module, c"DnsQueryRawResultFree".as_ptr().cast())?;
        Some(RawDnsApi {
            query: mem::transmute::<unsafe extern "system" fn() -> isize, DnsQueryRawFn>(query),
            cancel: mem::transmute::<unsafe extern "system" fn() -> isize, DnsCancelQueryRawFn>(
                cancel,
            ),
            free_result: mem::transmute::<
                unsafe extern "system" fn() -> isize,
                DnsQueryRawResultFreeFn,
            >(free_result),
        })
    }
}

/// Start one asynchronous Windows DNS query without carrying its raw-pointer request across await.
fn start_query(
    api: RawDnsApi,
    raw_query: &[u8],
    transport: Transport,
) -> io::Result<(PendingQuery, oneshot::Receiver<io::Result<Vec<u8>>>)> {
    let (mut query_packet, protocol) = prepare_query(raw_query, transport)?;
    let (sender, receiver) = oneshot::channel();
    let state = Arc::new(QueryState {
        sender: Mutex::new(Some(sender)),
        cancel: Mutex::new(DNS_QUERY_RAW_CANCEL::default()),
        api,
    });
    // This strong reference belongs to Windows until the completion callback reclaims it. It also
    // keeps the cancel handle alive after a timed-out future drops its own PendingQuery reference.
    let callback_state = Arc::into_raw(Arc::clone(&state));
    let request = DNS_QUERY_RAW_REQUEST {
        version: DNS_QUERY_RAW_REQUEST_VERSION1,
        resultsVersion: DNS_QUERY_RAW_RESULTS_VERSION1,
        dnsQueryRawSize: query_packet.len() as u32,
        dnsQueryRaw: query_packet.as_mut_ptr(),
        queryCompletionCallback: Some(query_complete),
        queryContext: callback_state.cast_mut().cast::<c_void>(),
        protocol,
        ..Default::default()
    };

    // SAFETY: the raw query only needs to live until DnsQueryRaw returns. The cancel handle is
    // protected by a stable Arc allocation that remains alive until the callback completes.
    let status = {
        let mut cancel = state
            .cancel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe { (api.query)(&request, &mut *cancel) }
    };
    if status != DNS_REQUEST_PENDING {
        // Windows did not accept the asynchronous request, so it will not invoke the callback.
        // SAFETY: reclaim exactly the strong reference created with Arc::into_raw above.
        unsafe { drop(Arc::from_raw(callback_state)) };
        return Err(Error::from_raw_os_error(status));
    }

    Ok((
        PendingQuery {
            state,
            completed: false,
        },
        receiver,
    ))
}

/// Windows completion callback. Copies the response before releasing the API-owned result.
unsafe extern "system" fn query_complete(
    query_context: *const c_void,
    query_results: *const DNS_QUERY_RAW_RESULT,
) {
    // SAFETY: every accepted request transfers exactly one Arc strong reference to Windows, which
    // invokes this callback exactly once, including after cancellation.
    let state = unsafe { Arc::from_raw(query_context.cast::<QueryState>()) };
    let result = copy_query_result(query_results);
    if !query_results.is_null() {
        // SAFETY: the result belongs to DnsQueryRaw and must be released after copying its buffer.
        unsafe { (state.api.free_result)(query_results) };
    }
    let sender = state
        .sender
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(sender) = sender {
        let _ = sender.send(result);
    }
}

fn copy_query_result(query_results: *const DNS_QUERY_RAW_RESULT) -> io::Result<Vec<u8>> {
    if query_results.is_null() {
        return Err(Error::other("Windows system DNS returned no result"));
    }

    // SAFETY: the pointer is valid for the duration of the completion callback.
    let result = unsafe { &*query_results };
    if result.queryStatus != ERROR_SUCCESS as i32 {
        return Err(Error::from_raw_os_error(result.queryStatus));
    }
    if result.queryRawResponse.is_null() || result.queryRawResponseSize == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Windows system DNS returned an empty response",
        ));
    }

    // SAFETY: Windows reports a response buffer of exactly `queryRawResponseSize` bytes.
    Ok(unsafe {
        slice::from_raw_parts(
            result.queryRawResponse,
            result.queryRawResponseSize as usize,
        )
        .to_vec()
    })
}

fn prepare_query(raw_query: &[u8], transport: Transport) -> io::Result<(Vec<u8>, u32)> {
    match transport {
        Transport::Udp => {
            let _: u32 = raw_query
                .len()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "DNS query is too large"))?;
            Ok((raw_query.to_vec(), DNS_PROTOCOL_UDP))
        }
        Transport::Tcp | Transport::Dot => {
            let len: u16 = raw_query.len().try_into().map_err(|_| {
                Error::new(ErrorKind::InvalidInput, "DNS-over-TCP query is too large")
            })?;
            let mut framed = Vec::with_capacity(raw_query.len() + 2);
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(raw_query);
            Ok((framed, DNS_PROTOCOL_TCP))
        }
    }
}

fn finish_response(response: Vec<u8>, transport: Transport) -> io::Result<Vec<u8>> {
    if transport == Transport::Udp {
        return Ok(response);
    }
    if response.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Windows system DNS returned a truncated TCP frame",
        ));
    }

    let declared = u16::from_be_bytes([response[0], response[1]]) as usize;
    if declared != response.len() - 2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Windows system DNS returned an invalid TCP frame length",
        ));
    }
    Ok(response[2..].to_vec())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_queries_and_responses_are_length_framed() {
        let query = [0x12, 0x34, 0x01, 0x00];
        let (framed, protocol) = prepare_query(&query, Transport::Tcp).unwrap();
        assert_eq!(protocol, DNS_PROTOCOL_TCP);
        assert_eq!(framed, [0, 4, 0x12, 0x34, 0x01, 0x00]);
        assert_eq!(finish_response(framed, Transport::Tcp).unwrap(), query);
    }

    #[test]
    fn malformed_tcp_responses_are_rejected() {
        let error = finish_response(vec![0, 4, 0x12], Transport::Tcp).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    #[ignore = "requires the Windows DNS Client and host network access"]
    async fn resolves_through_windows_dns_client() {
        // Standard recursive A query for example.com with transaction id 0x1234.
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let resolver = WindowsSystemResolver::new(Duration::from_secs(10));
        let response = resolver.query(&query, Transport::Udp).await.unwrap();
        assert!(response.len() >= 12);
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_ne!(u16::from_be_bytes([response[6], response[7]]), 0);
    }
}
