//! The FLOW and SOCKET layers: callouts at WFP's application layer enforcement (ALE) layers,
//! IPv4 and IPv6, which report what sockets do. Events have no packet: each handle's program runs
//! on an empty one, with the event's metadata (endpoints, protocol, process).
//!
//! | Event | ALE layer |
//! | --- | --- |
//! | FLOW: ESTABLISHED | `ALE_FLOW_ESTABLISHED` |
//! | FLOW: DELETED | the flow's deletion, through the context associated with it |
//! | SOCKET: BIND | `ALE_RESOURCE_ASSIGNMENT` |
//! | SOCKET: CONNECT | `ALE_AUTH_CONNECT` |
//! | SOCKET: LISTEN | `ALE_AUTH_LISTEN` |
//! | SOCKET: ACCEPT | `ALE_AUTH_RECV_ACCEPT` |
//! | SOCKET: CLOSE | `ALE_ENDPOINT_CLOSURE` |
//!
//! A SOCKET handle without SNIFF refuses what its filter matches (BIND, CONNECT, LISTEN and
//! ACCEPT: `FWP_ACTION_BLOCK`; a CLOSE cannot be refused) and reports it, unless DROP is set.
//!
//! Every flow a FLOW handle's callout sees gets a context (the flow handle, keyed in [`FLOWS`]),
//! so that its deletion comes back to the driver, which reports DELETED to the FLOW handles whose
//! filter matches it. The contexts go when the last FLOW handle closes.

use core::ffi::c_void;
use core::hash::{BuildHasher, Hasher};

use hashbrown::HashMap;

use avulse_abi::{Address, Flags, PROCESS_NAME_LEN};
use avulse_filter::{Event, Layer, Meta};
use avulse_proto::Link;

use crate::eval;
use crate::handle::Open;
use crate::lock::SpinLock;
use crate::sys;
use crate::wfp::{self, Callout};

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> sys::GUID {
    sys::GUID {
        Data1: a,
        Data2: b,
        Data3: c,
        Data4: d,
    }
}

/// The ALE layers (values from the WDK's `fwpmk.h`).
const FLOW_ESTABLISHED_V4: sys::GUID = guid(
    0xaf80_470a,
    0x5596,
    0x4c13,
    [0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67],
);
const FLOW_ESTABLISHED_V6: sys::GUID = guid(
    0x7021_d2b3,
    0xdfa4,
    0x406e,
    [0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd],
);
const RESOURCE_ASSIGNMENT_V4: sys::GUID = guid(
    0x1247_d66d,
    0x0b60,
    0x4a15,
    [0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c],
);
const RESOURCE_ASSIGNMENT_V6: sys::GUID = guid(
    0x55a6_50e1,
    0x5f0a,
    0x4eca,
    [0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c],
);
const AUTH_CONNECT_V4: sys::GUID = guid(
    0xc38d_57d1,
    0x05a7,
    0x4c33,
    [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
);
const AUTH_CONNECT_V6: sys::GUID = guid(
    0x4a72_393b,
    0x319f,
    0x44bc,
    [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
);
const AUTH_LISTEN_V4: sys::GUID = guid(
    0x88bb_5dad,
    0x76d7,
    0x4227,
    [0x9c, 0x71, 0xdf, 0x0a, 0x3e, 0xd7, 0xbe, 0x7e],
);
const AUTH_LISTEN_V6: sys::GUID = guid(
    0x7ac9_de24,
    0x17dd,
    0x4814,
    [0xb4, 0xbd, 0xa9, 0xfb, 0xc9, 0x5a, 0x32, 0x1b],
);
const AUTH_RECV_ACCEPT_V4: sys::GUID = guid(
    0xe1cd_9fe7,
    0xf4b5,
    0x4273,
    [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
);
const AUTH_RECV_ACCEPT_V6: sys::GUID = guid(
    0xa3b4_2c97,
    0x9f04,
    0x4672,
    [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
);
const ENDPOINT_CLOSURE_V4: sys::GUID = guid(
    0xb476_6427,
    0xe2a2,
    0x467a,
    [0xbd, 0x7e, 0xdb, 0xcd, 0x1b, 0xd8, 0x5a, 0x09],
);
const ENDPOINT_CLOSURE_V6: sys::GUID = guid(
    0xbb53_6ccd,
    0x4755,
    0x4ba9,
    [0x9f, 0xf7, 0xf9, 0xed, 0xf8, 0x69, 0x9c, 0x7b],
);

/// Where a layer's values are in its incoming values (`FWPS_FIELD_*`; the IPv6 layers number
/// them as the IPv4 ones do).
#[derive(Clone, Copy)]
struct Fields {
    local_addr: usize,
    local_port: usize,
    remote_addr: Option<usize>,
    remote_port: Option<usize>,
    /// None where the layer implies TCP (LISTEN).
    protocol: Option<usize>,
    direction: Option<usize>,
    flags: usize,
}

macro_rules! field {
    ($e:ident :: $f:ident) => {
        sys::$e::$f as usize
    };
}

const FLOW: Fields = Fields {
    local_addr: field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS
    ),
    local_port: field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT
    ),
    remote_addr: Some(field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS
    )),
    remote_port: Some(field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT
    )),
    protocol: Some(field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL
    )),
    direction: Some(field!(
        FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION
    )),
    flags: field!(FWPS_FIELDS_ALE_FLOW_ESTABLISHED_V4_::FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS),
};
const BIND: Fields = Fields {
    local_addr: field!(FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_::FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS),
    local_port: field!(FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_::FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT),
    remote_addr: None,
    remote_port: None,
    protocol: Some(field!(FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_::FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL)),
    direction: None,
    flags: field!(FWPS_FIELDS_ALE_RESOURCE_ASSIGNMENT_V4_::FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS),
};
const CONNECT: Fields = Fields {
    local_addr: field!(
        FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS
    ),
    local_port: field!(
        FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT
    ),
    remote_addr: Some(field!(
        FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS
    )),
    remote_port: Some(field!(
        FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
    )),
    protocol: Some(field!(
        FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
    )),
    direction: None,
    flags: field!(FWPS_FIELDS_ALE_AUTH_CONNECT_V4_::FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS),
};
const LISTEN: Fields = Fields {
    local_addr: field!(
        FWPS_FIELDS_ALE_AUTH_LISTEN_V4_::FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS
    ),
    local_port: field!(
        FWPS_FIELDS_ALE_AUTH_LISTEN_V4_::FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT
    ),
    remote_addr: None,
    remote_port: None,
    protocol: None,
    direction: None,
    flags: field!(FWPS_FIELDS_ALE_AUTH_LISTEN_V4_::FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS),
};
const ACCEPT: Fields = Fields {
    local_addr: field!(
        FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS
    ),
    local_port: field!(
        FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT
    ),
    remote_addr: Some(field!(
        FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS
    )),
    remote_port: Some(field!(
        FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT
    )),
    protocol: Some(field!(
        FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL
    )),
    direction: None,
    flags: field!(FWPS_FIELDS_ALE_AUTH_RECV_ACCEPT_V4_::FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS),
};
const CLOSE: Fields = Fields {
    local_addr: field!(
        FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS
    ),
    local_port: field!(
        FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT
    ),
    remote_addr: Some(field!(
        FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS
    )),
    remote_port: Some(field!(
        FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT
    )),
    protocol: Some(field!(
        FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL
    )),
    direction: None,
    flags: field!(FWPS_FIELDS_ALE_ENDPOINT_CLOSURE_V4_::FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_FLAGS),
};

/// One ALE hook.
#[derive(Clone, Copy)]
pub struct Hook {
    layer: sys::GUID,
    avulse: Layer,
    event: Event,
    ipv6: bool,
    fields: Fields,
}

const fn hook(layer: sys::GUID, event: Event, ipv6: bool, fields: Fields) -> Hook {
    let avulse = match event {
        Event::FlowEstablished => Layer::Flow,
        _ => Layer::Socket,
    };
    Hook {
        layer,
        avulse,
        event,
        ipv6,
        fields,
    }
}

pub const HOOKS: [Hook; 12] = [
    hook(FLOW_ESTABLISHED_V4, Event::FlowEstablished, false, FLOW),
    hook(FLOW_ESTABLISHED_V6, Event::FlowEstablished, true, FLOW),
    hook(RESOURCE_ASSIGNMENT_V4, Event::SocketBind, false, BIND),
    hook(RESOURCE_ASSIGNMENT_V6, Event::SocketBind, true, BIND),
    hook(AUTH_CONNECT_V4, Event::SocketConnect, false, CONNECT),
    hook(AUTH_CONNECT_V6, Event::SocketConnect, true, CONNECT),
    hook(AUTH_LISTEN_V4, Event::SocketListen, false, LISTEN),
    hook(AUTH_LISTEN_V6, Event::SocketListen, true, LISTEN),
    hook(AUTH_RECV_ACCEPT_V4, Event::SocketAccept, false, ACCEPT),
    hook(AUTH_RECV_ACCEPT_V6, Event::SocketAccept, true, ACCEPT),
    hook(ENDPOINT_CLOSURE_V4, Event::SocketClose, false, CLOSE),
    hook(ENDPOINT_CLOSURE_V6, Event::SocketClose, true, CLOSE),
];

macro_rules! classify_fns {
    ($($name:ident = $i:expr;)*) => {
        $(
            unsafe extern "C" fn $name(
                values: *const sys::FWPS_INCOMING_VALUES0,
                meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
                _layer_data: *mut c_void,
                _context: *const c_void,
                filter: *const sys::FWPS_FILTER3,
                _flow: u64,
                out: *mut sys::FWPS_CLASSIFY_OUT0,
            ) {
                // SAFETY: WFP passes valid pointers.
                unsafe { classify(&HOOKS[$i], values, meta, filter, out) }
            }
        )*
        const CLASSIFY: [sys::FWPS_CALLOUT_CLASSIFY_FN3; 12] = [$(Some($name)),*];
    };
}

classify_fns! {
    classify_0 = 0;
    classify_1 = 1;
    classify_2 = 2;
    classify_3 = 3;
    classify_4 = 4;
    classify_5 = 5;
    classify_6 = 6;
    classify_7 = 7;
    classify_8 = 8;
    classify_9 = 9;
    classify_10 = 10;
    classify_11 = 11;
}

/// The callout of `HOOKS[i]`.
pub fn callout(i: usize) -> Callout {
    let h = &HOOKS[i];
    Callout {
        layer: h.layer,
        avulse: h.avulse,
        classify: CLASSIFY[i],
        flow_delete: (h.avulse == Layer::Flow).then_some(flow_deleted as _),
        // FLOW handles only report, and closures cannot be refused.
        inspect: matches!(h.event, Event::FlowEstablished | Event::SocketClose),
    }
}

/// The flows whose deletion the driver waits for, by flow handle: the ESTABLISHED address
/// (with no handle's fields), and where the context is associated.
struct FlowEntry {
    addr: Address,
    layer_id: u16,
    callout_id: u32,
}

/// At most this many flows are followed; past it, flows end without a DELETED event.
const MAX_FLOWS: usize = 16_384;
/// A hash table, unlike a `BTreeMap`, can make room before an insert (`try_reserve`), so that a
/// flow is not followed when the pool is full, rather than panicking.
static FLOWS: SpinLock<HashMap<u64, FlowEntry, FlowHash>> =
    SpinLock::new(HashMap::with_hasher(FlowHash));

/// Hashes flow handles (opaque 64-bit values) by multiplication, so that every bit counts.
#[derive(Clone, Copy, Default)]
struct FlowHash;

impl BuildHasher for FlowHash {
    type Hasher = FlowHasher;

    fn build_hasher(&self) -> FlowHasher {
        FlowHasher(0)
    }
}

struct FlowHasher(u64);

impl Hasher for FlowHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn finish(&self) -> u64 {
        // hashbrown takes its control bits from the top and the bucket from the bottom.
        self.0 ^ (self.0 >> 32)
    }
}

/// Removes the context of every flow followed. Their deletion is not reported.
///
/// # Safety
///
/// At PASSIVE_LEVEL.
pub unsafe fn forget_flows() {
    let flows = core::mem::take(&mut *FLOWS.lock());
    for (handle, f) in &flows {
        // SAFETY: a context the driver associated; the flow-delete function finds no entry for
        // it any more.
        let _ = unsafe { sys::FwpsFlowRemoveContext0(*handle, f.layer_id, f.callout_id) };
    }
}

/// Frees the flow table's allocation, at unload.
pub fn free() {
    drop(core::mem::take(&mut *FLOWS.lock()));
}

/// The incoming value at `index`, if the layer has it.
///
/// # Safety
///
/// `values` is what WFP passed.
unsafe fn value<'a>(
    values: *const sys::FWPS_INCOMING_VALUES0,
    index: usize,
) -> Option<&'a sys::FWP_VALUE0> {
    // SAFETY: as above; the index is checked against the count.
    unsafe {
        let v = &*values;
        if index >= v.valueCount as usize {
            return None;
        }
        let value = &(*v.incomingValue.add(index)).value;
        (value.type_ != sys::FWP_DATA_TYPE_::FWP_EMPTY).then_some(value)
    }
}

/// An address value as 16 bytes, IPv4 as IPv4-mapped IPv6.
///
/// # Safety
///
/// `v` is a value of an address field of a layer of that family.
unsafe fn address_bytes(v: Option<&sys::FWP_VALUE0>, ipv6: bool) -> [u8; 16] {
    let Some(v) = v else {
        return if ipv6 { [0; 16] } else { mapped(0) };
    };
    // SAFETY: IPv6 addresses are FWP_BYTE_ARRAY16_TYPE, IPv4 ones FWP_UINT32 in host order.
    unsafe {
        if ipv6 {
            let p = v.__bindgen_anon_1.byteArray16;
            if p.is_null() {
                [0; 16]
            } else {
                (*p).byteArray16
            }
        } else {
            mapped(v.__bindgen_anon_1.uint32)
        }
    }
}

fn mapped(v4: u32) -> [u8; 16] {
    let mut a = [0; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12..].copy_from_slice(&v4.to_be_bytes());
    a
}

fn is_loopback(a: &[u8; 16]) -> bool {
    core::net::Ipv6Addr::from(*a).to_canonical().is_loopback()
}

/// The image name of a process path (`\device\harddiskvolume3\...\curl.exe` to `curl.exe`),
/// from UTF-16 bytes, as UTF-8 in `buf`. Cut where `buf` is full; nothing is allocated.
fn image_name<'a>(path: &[u8], buf: &'a mut [u8; PROCESS_NAME_LEN]) -> &'a str {
    let units = path.as_chunks::<2>().0;
    let end = units
        .iter()
        .position(|&c| c == [0, 0])
        .unwrap_or(units.len());
    let units = &units[..end];
    let start = units
        .iter()
        .rposition(|&c| c == [b'\\', 0])
        .map_or(0, |i| i + 1);
    let mut n = 0;
    for c in char::decode_utf16(units[start..].iter().map(|&c| u16::from_le_bytes(c))) {
        let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
        if n + c.len_utf8() > buf.len() {
            break;
        }
        n += c.encode_utf8(&mut buf[n..]).len();
    }
    // `n` bytes of whole characters.
    core::str::from_utf8(&buf[..n]).unwrap_or_default()
}

/// The address of the event `hook` reports, from the classify's values and metadata.
///
/// # Safety
///
/// What WFP passed.
unsafe fn event_address(
    hook: &Hook,
    values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
) -> Address {
    let f = &hook.fields;
    let mut a = Address::new(hook.avulse);
    a.timestamp = wfp::now_ns();
    a.event = hook.event;
    a.ipv6 = hook.ipv6;
    // SAFETY: what WFP passed.
    unsafe {
        let local = address_bytes(value(values, f.local_addr), hook.ipv6);
        let remote = address_bytes(f.remote_addr.and_then(|i| value(values, i)), hook.ipv6);
        let port = |i: Option<usize>| {
            i.and_then(|i| value(values, i))
                .map_or(0, |v| v.__bindgen_anon_1.uint16)
        };
        a.flow.local_addr = local;
        a.flow.remote_addr = remote;
        a.flow.local_port = port(Some(f.local_port));
        a.flow.remote_port = port(f.remote_port);
        a.flow.protocol = match f.protocol {
            Some(i) => value(values, i).map_or(0, |v| v.__bindgen_anon_1.uint8),
            None => 6,
        };
        a.outbound = match f.direction {
            Some(i) => value(values, i).is_some_and(|v| {
                v.__bindgen_anon_1.uint32 == sys::FWP_DIRECTION_::FWP_DIRECTION_OUTBOUND as u32
            }),
            None => hook.event == Event::SocketConnect,
        };
        let flags = wfp::value_u32(values, f.flags);
        a.loopback = flags & sys::FWP_CONDITION_FLAG_IS_LOOPBACK != 0
            || is_loopback(&local)
            || is_loopback(&remote);
        let m = &*meta;
        let has = |field: u32| m.currentMetadataValues & field != 0;
        if has(sys::FWPS_METADATA_FIELD_PROCESS_ID) {
            a.flow.process_id = m.processId as u32;
        }
        if has(sys::FWPS_METADATA_FIELD_PROCESS_PATH) && !m.processPath.is_null() {
            let blob = &*m.processPath;
            if !blob.data.is_null() {
                let path = core::slice::from_raw_parts(blob.data, blob.size as usize);
                let mut buf = [0; PROCESS_NAME_LEN];
                a.flow.set_process_name(image_name(path, &mut buf));
            }
        }
        if has(sys::FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) {
            a.flow.endpoint_id = m.transportEndpointHandle;
        }
        if has(sys::FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE) {
            a.flow.parent_endpoint_id = m.parentEndpointHandle;
        }
    }
    a
}

/// Whether `open`'s program matches the event `addr`; `None` if it could not run.
fn matches(open: &Open, addr: &Address) -> Option<bool> {
    let mut m: Meta<'_> = addr.meta();
    m.priority = open.priority;
    // The `random*` fields: a hash of the endpoint, as on Linux.
    m.hash = addr
        .flow
        .endpoint_id
        .to_ne_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |h, &b| {
            (h ^ b as u64).wrapping_mul(0x0100_0000_01b3)
        });
    eval::evaluate(open.program(), &[], Link::Ip, &m)
}

/// Reports the event `hook` sees to the handle the filter belongs to, and refuses it if the
/// handle is a SOCKET handle without SNIFF whose filter matches.
unsafe fn classify(
    hook: &Hook,
    values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    filter: *const sys::FWPS_FILTER3,
    out: *mut sys::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP passes a valid `out` and filter.
    let (out, filter) = unsafe { (&mut *out, &*filter) };
    out.actionType = sys::FWP_ACTION_CONTINUE;
    let Some(open) = wfp::handle(filter.context) else {
        return;
    };
    if open.idle() {
        return;
    }
    // SAFETY: WFP passes valid values.
    let flags = unsafe { wfp::value_u32(values, hook.fields.flags) };
    // A connection authorized again (after a policy change) is not a new event.
    if flags & sys::FWP_CONDITION_FLAG_IS_REAUTHORIZE != 0 {
        return;
    }
    // SAFETY: as above.
    let addr = unsafe { event_address(hook, values, meta) };
    if hook.avulse == Layer::Flow {
        // SAFETY: as above.
        unsafe { follow(values, meta, filter, &addr) };
    }
    // Fail open: an event that could not be evaluated goes on, unreported.
    if matches(&open, &addr) != Some(true) {
        return;
    }
    let sniff = open.flags.contains(Flags::SNIFF);
    let refuse = !sniff
        && hook.event != Event::SocketClose
        && out.rights & sys::FWPS_RIGHT_ACTION_WRITE != 0;
    if open.flags.contains(Flags::DROP) {
        open.mutable.lock().stats.dropped += 1;
    } else {
        let mut addr = addr;
        addr.sniffed = !refuse;
        open.deliver(addr, alloc::vec::Vec::new());
    }
    if refuse {
        out.actionType = sys::FWP_ACTION_BLOCK;
        out.rights &= !sys::FWPS_RIGHT_ACTION_WRITE;
    }
}

/// Associates a context with the flow of an ESTABLISHED event, once, so that its deletion comes
/// back to [`flow_deleted`].
///
/// # Safety
///
/// What WFP passed.
unsafe fn follow(
    values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    filter: &sys::FWPS_FILTER3,
    addr: &Address,
) {
    // SAFETY: what WFP passed.
    let (m, layer_id) = unsafe { (&*meta, (*values).layerId) };
    if m.currentMetadataValues & sys::FWPS_METADATA_FIELD_FLOW_HANDLE == 0 {
        return;
    }
    let handle = m.flowHandle;
    let callout_id = filter.action.calloutId;
    {
        let mut flows = FLOWS.lock();
        if flows.contains_key(&handle) || flows.len() >= MAX_FLOWS || flows.try_reserve(1).is_err()
        {
            return;
        }
        let mut addr = *addr;
        addr.sniffed = true;
        flows.insert(
            handle,
            FlowEntry {
                addr,
                layer_id,
                callout_id,
            },
        );
    }
    // SAFETY: a flow of this layer, and this classify's callout.
    let status = unsafe { sys::FwpsFlowAssociateContext0(handle, layer_id, callout_id, handle) };
    if status != sys::STATUS_SUCCESS {
        FLOWS.lock().remove(&handle);
    }
}

/// A flow the driver follows ended: DELETED, to every FLOW handle whose filter matches it.
unsafe extern "C" fn flow_deleted(_layer_id: u16, _callout_id: u32, context: u64) {
    let Some(entry) = FLOWS.lock().remove(&context) else {
        return;
    };
    let mut addr = entry.addr;
    addr.event = Event::FlowDeleted;
    addr.timestamp = wfp::now_ns();
    for open in wfp::handles_at(Layer::Flow) {
        if !open.idle() && matches(&open, &addr) == Some(true) {
            open.deliver(addr, alloc::vec::Vec::new());
        }
    }
}
