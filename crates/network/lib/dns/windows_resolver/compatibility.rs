//! `DnsQueryEx` compatibility backend for Windows builds without `DnsQueryRaw`.

use std::ffi::{CStr, c_void};
use std::io::{self, Error, ErrorKind};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, Query, ResponseCode};
use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{
    DNS_ERROR_RCODE_FORMAT_ERROR, DNS_ERROR_RCODE_NAME_ERROR, DNS_ERROR_RCODE_NOT_IMPLEMENTED,
    DNS_ERROR_RCODE_REFUSED, DNS_ERROR_RCODE_SERVER_FAILURE, DNS_INFO_NO_RECORDS,
    DNS_REQUEST_PENDING, ERROR_SUCCESS,
};
use windows_sys::Win32::NetworkManagement::Dns as dns;

use crate::dns::common::transport::Transport;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_RECORDS: usize = u16::MAX as usize;
const MAX_RDATA: usize = u16::MAX as usize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct GuestQuery {
    metadata: Metadata,
    query: Query,
}

struct QueryState {
    sender: Mutex<Option<oneshot::Sender<io::Result<Vec<u8>>>>>,
    cancel: Mutex<dns::DNS_QUERY_CANCEL>,
    result: Mutex<dns::DNS_QUERY_RESULT>,
    guest: GuestQuery,
    // Some Windows implementations retain QueryName until completion, so it shares the callback's
    // stable Arc allocation instead of borrowing a temporary UTF-16 buffer.
    query_name: Vec<u16>,
}

struct PendingQuery {
    state: Arc<QueryState>,
    completed: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for PendingQuery {
    fn drop(&mut self) {
        if !self.completed {
            let cancel = lock(&self.state.cancel);
            // SAFETY: the accepted query owns this cancel handle, which stays alive in the Arc.
            unsafe {
                let _ = dns::DnsCancelQuery(&*cancel);
            }
        }
    }
}

// SAFETY: the only non-Send fields are opaque pointers inside DNS_QUERY_RESULT. Windows owns their
// pointees until completion, and every access to the result structure is serialized by its Mutex.
// QueryState itself remains at a stable Arc address until the callback releases its share.
unsafe impl Send for QueryState {}
unsafe impl Sync for QueryState {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn query(
    raw_query: &[u8],
    transport: Transport,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let (mut pending, receiver) = start_query(raw_query, transport)?;
    let response = tokio::time::timeout(timeout, receiver)
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "Windows system DNS query timed out"))?
        .map_err(|_| Error::other("Windows system DNS callback was dropped"))??;
    pending.completed = true;
    Ok(response)
}

fn start_query(
    raw_query: &[u8],
    transport: Transport,
) -> io::Result<(PendingQuery, oneshot::Receiver<io::Result<Vec<u8>>>)> {
    let guest = parse_guest_query(raw_query)?;
    let query_name = guest
        .query
        .name()
        .to_utf8()
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let (sender, receiver) = oneshot::channel();
    let state = Arc::new(QueryState {
        sender: Mutex::new(Some(sender)),
        cancel: Mutex::new(dns::DNS_QUERY_CANCEL::default()),
        result: Mutex::new(dns::DNS_QUERY_RESULT {
            Version: dns::DNS_QUERY_RESULTS_VERSION1,
            ..Default::default()
        }),
        guest,
        query_name,
    });
    let callback_state = Arc::into_raw(Arc::clone(&state));
    let request = dns::DNS_QUERY_REQUEST {
        Version: dns::DNS_QUERY_REQUEST_VERSION1,
        QueryName: state.query_name.as_ptr(),
        QueryType: state.guest.query.query_type().into(),
        QueryOptions: u64::from(
            dns::DNS_QUERY_RETURN_MESSAGE
                | dns::DNS_QUERY_TREAT_AS_FQDN
                | if transport == Transport::Udp {
                    0
                } else {
                    dns::DNS_QUERY_USE_TCP_ONLY
                },
        ),
        pQueryCompletionCallback: Some(query_complete),
        pQueryContext: callback_state.cast_mut().cast::<c_void>(),
        ..Default::default()
    };

    let status = {
        let mut result = lock(&state.result);
        let mut cancel = lock(&state.cancel);
        // SAFETY: all pointer targets live in the stable Arc until synchronous completion or the
        // callback. The local request itself only needs to live until DnsQueryEx returns.
        unsafe { dns::DnsQueryEx(&request, &mut *result, &mut *cancel) }
    };
    let completed = status != DNS_REQUEST_PENDING;
    if completed {
        // DnsQueryEx promises that a non-pending completion will not invoke the callback.
        // SAFETY: reclaim the callback reference because Windows did not take ownership of it.
        unsafe { drop(Arc::from_raw(callback_state)) };
        let converted = {
            let mut result = lock(&state.result);
            if status != ERROR_SUCCESS as i32 {
                result.QueryStatus = status;
            }
            take_result(&state.guest, &mut result)
        };
        send(&state.sender, converted);
    }

    Ok((PendingQuery { state, completed }, receiver))
}

unsafe extern "system" fn query_complete(
    context: *const c_void,
    result: *mut dns::DNS_QUERY_RESULT,
) {
    // SAFETY: each pending query gives Windows exactly one Arc reference to return here.
    let state = unsafe { Arc::from_raw(context.cast::<QueryState>()) };
    let converted = if result.is_null() {
        Err(Error::other("Windows system DNS returned no result"))
    } else {
        let mut owned_result = lock(&state.result);
        if !ptr::eq(result, &mut *owned_result) {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Windows system DNS returned an unexpected result pointer",
            ))
        } else {
            take_result(&state.guest, &mut owned_result)
        }
    };
    send(&state.sender, converted);
}

fn parse_guest_query(raw_query: &[u8]) -> io::Result<GuestQuery> {
    let message =
        Message::from_vec(raw_query).map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
    if message.metadata.message_type != MessageType::Query || message.queries.len() != 1 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "DnsQueryEx compatibility requires exactly one DNS question",
        ));
    }
    if u16::from(message.queries[0].query_class()) != dns::DNS_CLASS_INTERNET as u16 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "DnsQueryEx compatibility only supports the IN class",
        ));
    }
    Ok(GuestQuery {
        metadata: message.metadata,
        query: message.queries[0].clone(),
    })
}

fn take_result(guest: &GuestQuery, result: &mut dns::DNS_QUERY_RESULT) -> io::Result<Vec<u8>> {
    let records = result.pQueryRecords;
    result.pQueryRecords = ptr::null_mut();
    let response = build_response(guest, result.QueryStatus, records);
    if !records.is_null() {
        // SAFETY: DnsQueryEx allocates the list and requires this matching free operation.
        unsafe { dns::DnsFree(records.cast(), dns::DnsFreeRecordList) };
    }
    response
}

fn build_response(
    guest: &GuestQuery,
    status: i32,
    mut native: *mut dns::DNS_RECORDA,
) -> io::Result<Vec<u8>> {
    let mut response = Message::new(
        guest.metadata.id,
        MessageType::Response,
        guest.metadata.op_code,
    );
    response.metadata = Metadata::response_from_request(&guest.metadata);
    response.metadata.recursion_available = true;
    response.metadata.response_code = response_code(status)?;
    response.add_query(guest.query.clone());

    let mut count = 0;
    while !native.is_null() {
        count += 1;
        if count > MAX_RECORDS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Windows system DNS returned too many records",
            ));
        }
        // SAFETY: list nodes stay alive until take_result frees the complete list.
        let record = unsafe { &*native };
        let next = record.pNext;
        let section = unsafe { record.Flags.DW } & dns::DNSREC_SECTION;
        // DnsQueryEx does not retain the complete request-side EDNS contract. Omitting OPT is safer
        // than reflecting request-only options or emitting a malformed pseudo-record.
        if section != dns::DNSREC_QUESTION && record.wType != dns::DNS_TYPE_OPT {
            let converted = convert_record(record)?;
            match section {
                dns::DNSREC_ANSWER => response.add_answer(converted),
                dns::DNSREC_AUTHORITY => response.add_authority(converted),
                dns::DNSREC_ADDITIONAL => response.add_additional(converted),
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Windows system DNS returned an invalid record section",
                    ));
                }
            };
        }
        native = next;
    }
    response
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

fn response_code(status: i32) -> io::Result<ResponseCode> {
    match status as u32 {
        ERROR_SUCCESS => Ok(ResponseCode::NoError),
        value if value == DNS_INFO_NO_RECORDS as u32 => Ok(ResponseCode::NoError),
        DNS_ERROR_RCODE_FORMAT_ERROR => Ok(ResponseCode::FormErr),
        DNS_ERROR_RCODE_SERVER_FAILURE => Ok(ResponseCode::ServFail),
        DNS_ERROR_RCODE_NAME_ERROR => Ok(ResponseCode::NXDomain),
        DNS_ERROR_RCODE_NOT_IMPLEMENTED => Ok(ResponseCode::NotImp),
        DNS_ERROR_RCODE_REFUSED => Ok(ResponseCode::Refused),
        _ => Err(Error::from_raw_os_error(status)),
    }
}

fn convert_record(native: &dns::DNS_RECORDA) -> io::Result<Record> {
    let name = read_name(native.pName)?;
    let record_type = RecordType::from(native.wType);
    let rdata = convert_rdata(native)?;
    if rdata.is_empty() {
        return Ok(Record::update0(name, native.dwTtl, record_type));
    }
    Ok(Record::from_rdata(
        name,
        native.dwTtl,
        RData::Unknown {
            code: record_type,
            rdata: NULL::with(rdata),
        },
    ))
}

fn convert_rdata(native: &dns::DNS_RECORDA) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    // Windows fields are host-order structures, not wire bytes. Each supported union member is
    // converted explicitly so native padding and ARM64 alignment never leak into the DNS message.
    unsafe {
        match native.wType {
            // IP4_ADDRESS stores the network-order bytes directly in the native DWORD.
            dns::DNS_TYPE_A => out.extend_from_slice(&native.Data.A.IpAddress.to_ne_bytes()),
            dns::DNS_TYPE_AAAA => out.extend_from_slice(&native.Data.AAAA.Ip6Address.IP6Byte),
            dns::DNS_TYPE_NS
            | dns::DNS_TYPE_CNAME
            | dns::DNS_TYPE_PTR
            | dns::DNS_TYPE_DNAME
            | dns::DNS_TYPE_MB
            | dns::DNS_TYPE_MD
            | dns::DNS_TYPE_MF
            | dns::DNS_TYPE_MG
            | dns::DNS_TYPE_MR => write_name(&mut out, native.Data.PTR.pNameHost)?,
            dns::DNS_TYPE_SOA => {
                let data = &native.Data.SOA;
                write_name(&mut out, data.pNamePrimaryServer)?;
                write_name(&mut out, data.pNameAdministrator)?;
                for value in [
                    data.dwSerialNo,
                    data.dwRefresh,
                    data.dwRetry,
                    data.dwExpire,
                    data.dwDefaultTtl,
                ] {
                    write_u32(&mut out, value);
                }
            }
            dns::DNS_TYPE_MINFO | dns::DNS_TYPE_RP => {
                let data = &native.Data.MINFO;
                write_name(&mut out, data.pNameMailbox)?;
                write_name(&mut out, data.pNameErrorsMailbox)?;
            }
            dns::DNS_TYPE_MX | dns::DNS_TYPE_AFSDB | dns::DNS_TYPE_RT => {
                let data = &native.Data.MX;
                write_u16(&mut out, data.wPreference);
                write_name(&mut out, data.pNameExchange)?;
            }
            dns::DNS_TYPE_HINFO | dns::DNS_TYPE_ISDN | dns::DNS_TYPE_TEXT | dns::DNS_TYPE_X25 => {
                write_txt(&mut out, &native.Data.TXT)?
            }
            dns::DNS_TYPE_SRV => {
                let data = &native.Data.SRV;
                write_u16(&mut out, data.wPriority);
                write_u16(&mut out, data.wWeight);
                write_u16(&mut out, data.wPort);
                write_name(&mut out, data.pNameTarget)?;
            }
            dns::DNS_TYPE_NAPTR => {
                let data = &native.Data.NAPTR;
                write_u16(&mut out, data.wOrder);
                write_u16(&mut out, data.wPreference);
                write_character_string(&mut out, data.pFlags)?;
                write_character_string(&mut out, data.pService)?;
                write_character_string(&mut out, data.pRegularExpression)?;
                write_name(&mut out, data.pReplacement)?;
            }
            dns::DNS_TYPE_DS => {
                let data = &native.Data.DS;
                write_u16(&mut out, data.wKeyTag);
                out.extend_from_slice(&[data.chAlgorithm, data.chDigestType]);
                append(&mut out, data.Digest.as_ptr(), data.wDigestLength as usize)?;
            }
            dns::DNS_TYPE_KEY | dns::DNS_TYPE_DNSKEY => {
                let data = &native.Data.KEY;
                write_u16(&mut out, data.wFlags);
                out.extend_from_slice(&[data.chProtocol, data.chAlgorithm]);
                append(&mut out, data.Key.as_ptr(), data.wKeyLength as usize)?;
            }
            dns::DNS_TYPE_SIG | dns::DNS_TYPE_RRSIG => {
                let data = &native.Data.SIG;
                write_u16(&mut out, data.wTypeCovered);
                out.extend_from_slice(&[data.chAlgorithm, data.chLabelCount]);
                write_u32(&mut out, data.dwOriginalTtl);
                write_u32(&mut out, data.dwExpiration);
                write_u32(&mut out, data.dwTimeSigned);
                write_u16(&mut out, data.wKeyTag);
                write_name(&mut out, data.pNameSigner)?;
                append(
                    &mut out,
                    data.Signature.as_ptr(),
                    data.wSignatureLength as usize,
                )?;
            }
            dns::DNS_TYPE_NSEC => {
                let data = &native.Data.NSEC;
                write_name(&mut out, data.pNextDomainName)?;
                append(
                    &mut out,
                    data.TypeBitMaps.as_ptr(),
                    data.wTypeBitMapsLength as usize,
                )?;
            }
            dns::DNS_TYPE_NSEC3 => {
                let data = &native.Data.NSEC3;
                out.extend_from_slice(&[data.chAlgorithm, data.bFlags]);
                write_u16(&mut out, data.wIterations);
                out.push(data.bSaltLength);
                let length = data.bSaltLength as usize
                    + data.bHashLength as usize
                    + data.wTypeBitMapsLength as usize;
                append(&mut out, data.chData.as_ptr(), length)?;
            }
            dns::DNS_TYPE_NSEC3PARAM => {
                let data = &native.Data.NSEC3PARAM;
                out.extend_from_slice(&[data.chAlgorithm, data.bFlags]);
                write_u16(&mut out, data.wIterations);
                out.push(data.bSaltLength);
                append(&mut out, data.pbSalt.as_ptr(), data.bSaltLength as usize)?;
            }
            dns::DNS_TYPE_TLSA => {
                let data = &native.Data.TLSA;
                out.extend_from_slice(&[data.bCertUsage, data.bSelector, data.bMatchingType]);
                append(
                    &mut out,
                    data.bCertificateAssociationData.as_ptr(),
                    data.bCertificateAssociationDataLength as usize,
                )?;
            }
            dns::DNS_TYPE_NULL
            | dns::DNS_TYPE_WKS
            | dns::DNS_TYPE_LOC
            | dns::DNS_TYPE_ATMA
            | dns::DNS_TYPE_DHCID
            | dns::DNS_TYPE_SVCB
            | dns::DNS_TYPE_HTTPS
            | dns::DNS_TYPE_NXT
            | dns::DNS_TYPE_TKEY
            | dns::DNS_TYPE_TSIG
            | dns::DNS_TYPE_WINS
            | dns::DNS_TYPE_WINSR => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "DnsQueryEx returned a record type that requires specialized conversion",
                ));
            }
            _ => {
                // Windows represents record types without a dedicated union member as UNKNOWN.
                let data = &native.Data.UNKNOWN;
                append(&mut out, data.bData.as_ptr(), data.dwByteCount as usize)?;
            }
        }
    }
    if out.len() > MAX_RDATA {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Windows system DNS returned oversized record data",
        ));
    }
    Ok(out)
}

unsafe fn write_txt(out: &mut Vec<u8>, data: &dns::DNS_TXT_DATAA) -> io::Result<()> {
    let count = data.dwStringCount as usize;
    if count > MAX_RDATA {
        return Err(Error::new(ErrorKind::InvalidData, "invalid DNS TXT count"));
    }
    // SAFETY: Windows allocates dwStringCount pointers in this flexible array.
    for &text in unsafe { slice::from_raw_parts(data.pStringArray.as_ptr(), count) } {
        write_character_string(out, text)?;
    }
    Ok(())
}

fn read_name(value: *const u8) -> io::Result<Name> {
    let text = std::str::from_utf8(read_c_string(value)?)
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    Name::from_ascii(text).map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

fn write_name(out: &mut Vec<u8>, value: *const u8) -> io::Result<()> {
    for label in &read_name(value)? {
        out.push(
            label
                .len()
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "oversized DNS name label"))?,
        );
        out.extend_from_slice(label);
    }
    out.push(0);
    Ok(())
}

fn write_character_string(out: &mut Vec<u8>, value: *const u8) -> io::Result<()> {
    let bytes = read_c_string(value)?;
    out.push(
        bytes
            .len()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "oversized DNS character string"))?,
    );
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_c_string<'a>(value: *const u8) -> io::Result<&'a [u8]> {
    if value.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "null DNS string pointer",
        ));
    }
    // SAFETY: DnsQueryEx strings are NUL-terminated and live with the record list.
    Ok(unsafe { CStr::from_ptr(value.cast()).to_bytes() })
}

fn append(out: &mut Vec<u8>, value: *const u8, length: usize) -> io::Result<()> {
    if length > MAX_RDATA || (length > 0 && value.is_null()) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid DNS data length",
        ));
    }
    // SAFETY: the API-provided length is bounded and the record list remains alive.
    out.extend_from_slice(unsafe { slice::from_raw_parts(value, length) });
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn send(sender: &Mutex<Option<oneshot::Sender<io::Result<Vec<u8>>>>>, result: io::Result<Vec<u8>>) {
    if let Some(sender) = lock(sender).take() {
        let _ = sender.send(result);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const EXAMPLE_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn parses_single_internet_question() {
        let query = parse_guest_query(EXAMPLE_QUERY).unwrap();
        assert_eq!(query.metadata.id, 0x1234);
        assert_eq!(query.query.name().to_utf8(), "example.com.");
    }

    #[test]
    fn preserves_native_ipv4_network_bytes() {
        let native = dns::DNS_RECORDA {
            wType: dns::DNS_TYPE_A,
            Data: dns::DNS_RECORDA_1 {
                A: dns::DNS_A_DATA {
                    IpAddress: u32::from_ne_bytes([192, 0, 2, 1]),
                },
            },
            ..Default::default()
        };
        assert_eq!(convert_rdata(&native).unwrap(), [192, 0, 2, 1]);
    }

    #[tokio::test]
    #[ignore = "requires the Windows DNS Client and host network access"]
    async fn resolves_through_dns_query_ex() {
        let response = query(EXAMPLE_QUERY, Transport::Udp, Duration::from_secs(10))
            .await
            .unwrap();
        let message = Message::from_vec(&response).unwrap();
        assert_eq!(message.metadata.id, 0x1234);
        assert!(!message.answers.is_empty());
    }
}
