//! The WFP side: callouts at the IP packet and forward layers, IPv4 and IPv6, which run each open
//! handle's program on the packets of its layer, and those of the ALE layers (`ale`), for the
//! FLOW and SOCKET layers.
//!
//! The callouts are registered when the driver loads, and added to the base filtering engine, with
//! a sublayer, in a dynamic session that the driver closes at unload (which removes everything it
//! added). Opening a handle adds one WFP filter per layer it covers, whose weight follows the
//! handle's priority (the higher, the earlier) and whose context is the handle's id in
//! [`HANDLES`]; closing it deletes them. The classify function finds the handle by that id, so a
//! classify that runs while the handle closes still holds a reference to what it uses.

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use avulse_abi::{Address, Flags};
use avulse_filter::{Layer, Meta};
use avulse_proto::Link;

use crate::handle::Open;
use crate::lock::SpinLock;
use crate::sys::{self, w};
use crate::{ale, eval, inject};

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> sys::GUID {
    sys::GUID {
        Data1: a,
        Data2: b,
        Data3: c,
        Data4: d,
    }
}

/// Our sublayer and callouts.
const SUBLAYER: sys::GUID = guid(
    0x7c2e_4a91,
    0x5d3b,
    0x4f80,
    [0xa6, 0x1c, 0x39, 0xe2, 0x0b, 0x54, 0xd7, 0x10],
);
const fn callout_key(n: u8) -> sys::GUID {
    guid(
        0x7c2e_4a91,
        0x5d3b,
        0x4f80,
        [0xa6, 0x1c, 0x39, 0xe2, 0x0b, 0x54, 0xd7, 0x11 + n],
    )
}

/// The layers, as `windows-drivers-rs` has no constants for them (they are `extern` GUIDs, defined
/// only under INITGUID; values from the WDK's `fwpmk.h`).
const INBOUND_IPPACKET_V4: sys::GUID = guid(
    0xc86f_d1bf,
    0x21cd,
    0x497e,
    [0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58],
);
const INBOUND_IPPACKET_V6: sys::GUID = guid(
    0xf520_32cb,
    0x991c,
    0x46e7,
    [0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca],
);
const OUTBOUND_IPPACKET_V4: sys::GUID = guid(
    0x1e5c_9fae,
    0x8a84,
    0x4135,
    [0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd],
);
const OUTBOUND_IPPACKET_V6: sys::GUID = guid(
    0xa3b3_ab6b,
    0x3564,
    0x488c,
    [0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63],
);
const IPFORWARD_V4: sys::GUID = guid(
    0xa82a_cc24,
    0x4ee1,
    0x4ee1,
    [0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4],
);
const IPFORWARD_V6: sys::GUID = guid(
    0x7b96_4818,
    0x19c7,
    0x493a,
    [0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c],
);

/// One hook: a WFP layer and how to read its packets and fields.
#[derive(Clone, Copy)]
struct Hook {
    layer: sys::GUID,
    /// NETWORK or NETWORK_FORWARD.
    avulse: Layer,
    outbound: bool,
    ipv6: bool,
    /// Indexes of the interface, sub-interface and flags fields in the incoming values
    /// (`FWPS_FIELD_*`; they differ between the layers).
    if_idx: usize,
    sub_if_idx: usize,
    flags: usize,
}

const HOOKS: [Hook; 6] = [
    Hook {
        layer: INBOUND_IPPACKET_V4,
        avulse: Layer::Network,
        outbound: false,
        ipv6: false,
        if_idx: 4,
        sub_if_idx: 5,
        flags: 6,
    },
    Hook {
        layer: INBOUND_IPPACKET_V6,
        avulse: Layer::Network,
        outbound: false,
        ipv6: true,
        if_idx: 4,
        sub_if_idx: 5,
        flags: 6,
    },
    Hook {
        layer: OUTBOUND_IPPACKET_V4,
        avulse: Layer::Network,
        outbound: true,
        ipv6: false,
        if_idx: 4,
        sub_if_idx: 5,
        flags: 6,
    },
    Hook {
        layer: OUTBOUND_IPPACKET_V6,
        avulse: Layer::Network,
        outbound: true,
        ipv6: true,
        if_idx: 4,
        sub_if_idx: 5,
        flags: 6,
    },
    // The forward layers: the destination interface, as WinDivert reports it.
    Hook {
        layer: IPFORWARD_V4,
        avulse: Layer::NetworkForward,
        outbound: true,
        ipv6: false,
        if_idx: 7,
        sub_if_idx: 8,
        flags: 9,
    },
    Hook {
        layer: IPFORWARD_V6,
        avulse: Layer::NetworkForward,
        outbound: true,
        ipv6: true,
        if_idx: 7,
        sub_if_idx: 8,
        flags: 9,
    },
];

/// The packet layers' classify functions, in the order of [`HOOKS`].
const PACKET_CLASSIFY: [sys::FWPS_CALLOUT_CLASSIFY_FN3; 6] = [
    Some(classify_0),
    Some(classify_1),
    Some(classify_2),
    Some(classify_3),
    Some(classify_4),
    Some(classify_5),
];

/// One callout of the driver: its WFP layer, the avulse layer it serves and its functions.
#[derive(Clone, Copy)]
pub struct Callout {
    pub layer: sys::GUID,
    pub avulse: Layer,
    pub classify: sys::FWPS_CALLOUT_CLASSIFY_FN3,
    pub flow_delete: sys::FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0,
    /// The layer cannot block: its filters inspect.
    pub inspect: bool,
}

/// Every callout: the packet layers', then the ALE layers'.
const CALLOUTS: usize = HOOKS.len() + ale::HOOKS.len();

fn callout(i: usize) -> Callout {
    match HOOKS.get(i) {
        Some(h) => Callout {
            layer: h.layer,
            avulse: h.avulse,
            classify: PACKET_CLASSIFY[i],
            flow_delete: None,
            inspect: false,
        },
        None => ale::callout(i - HOOKS.len()),
    }
}

static ENGINE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CALLOUT_IDS: [AtomicU32; CALLOUTS] = [const { AtomicU32::new(0) }; CALLOUTS];

/// The open handles the hooks serve, by id (the WFP filters' context).
static HANDLES: SpinLock<BTreeMap<u64, Arc<Open>>> = SpinLock::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// `QueryPerformanceCounter`'s frequency, for timestamps in nanoseconds.
static FREQUENCY: AtomicU64 = AtomicU64::new(0);

macro_rules! check {
    ($e:expr) => {{
        // SAFETY: the engine is open and every pointer argument is valid for the call.
        let status = unsafe { $e };
        if status != sys::STATUS_SUCCESS {
            return status;
        }
    }};
}

/// Registers the callouts with `device`, opens the engine and adds the sublayer and callouts.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, from `DriverEntry`.
pub unsafe fn register(device: *mut sys::DEVICE_OBJECT) -> sys::NTSTATUS {
    let mut freq = 0i64;
    // SAFETY: plain call.
    unsafe { sys::KeQueryPerformanceCounter((&raw mut freq).cast()) };
    FREQUENCY.store(freq as u64, Ordering::Relaxed);
    for (i, slot) in CALLOUT_IDS.iter().enumerate() {
        let c = callout(i);
        let callout = sys::FWPS_CALLOUT3 {
            calloutKey: callout_key(i as u8),
            flags: 0,
            classifyFn: c.classify,
            notifyFn: Some(notify),
            flowDeleteFn: c.flow_delete,
        };
        let mut id = 0;
        check!(sys::FwpsCalloutRegister3(device.cast(), &callout, &mut id));
        slot.store(id, Ordering::Release);
    }
    let session = sys::FWPM_SESSION0 {
        flags: sys::FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut engine = null_mut();
    check!(sys::FwpmEngineOpen0(
        null(),
        sys::RPC_C_AUTHN_WINNT,
        null_mut(),
        &session,
        &mut engine
    ));
    ENGINE.store(engine, Ordering::Release);
    // SAFETY: the engine is open.
    let status = unsafe { add_objects(engine) };
    if status != sys::STATUS_SUCCESS {
        // SAFETY: as above.
        let _ = unsafe { sys::FwpmTransactionAbort0(engine) };
    }
    status
}

unsafe fn add_objects(engine: sys::HANDLE) -> sys::NTSTATUS {
    check!(sys::FwpmTransactionBegin0(engine, 0));
    let sublayer = sys::FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER,
        displayData: sys::FWPM_DISPLAY_DATA0 {
            name: w!("avulse").as_ptr().cast_mut(),
            description: null_mut(),
        },
        weight: 0x8000,
        ..Default::default()
    };
    check!(sys::FwpmSubLayerAdd0(engine, &sublayer, null_mut()));
    for i in 0..CALLOUTS {
        let h = callout(i);
        let callout = sys::FWPM_CALLOUT0 {
            calloutKey: callout_key(i as u8),
            displayData: sys::FWPM_DISPLAY_DATA0 {
                name: w!("avulse").as_ptr().cast_mut(),
                description: null_mut(),
            },
            applicableLayer: h.layer,
            ..Default::default()
        };
        check!(sys::FwpmCalloutAdd0(
            engine,
            &callout,
            null_mut(),
            null_mut()
        ));
    }
    check!(sys::FwpmTransactionCommit0(engine));
    sys::STATUS_SUCCESS
}

/// Closes the engine (removing every object of the session, the handles' filters included),
/// removes the flows' contexts and unregisters the callouts.
///
/// # Safety
///
/// At PASSIVE_LEVEL, at unload. No handle is open: the I/O manager unloads a driver whose files
/// are all closed.
pub unsafe fn unregister() {
    // An emptied BTreeMap keeps its root node allocated: free it, or Driver Verifier reports the
    // pool as leaked at unload.
    let handles = core::mem::take(&mut *HANDLES.lock());
    drop(handles);
    let engine = ENGINE.swap(null_mut(), Ordering::AcqRel);
    if !engine.is_null() {
        // SAFETY: the engine is open.
        let _ = unsafe { sys::FwpmEngineClose0(engine) };
    }
    // A callout with flow contexts cannot be unregistered.
    // SAFETY: at PASSIVE_LEVEL.
    unsafe { ale::forget_flows() };
    ale::free();
    for id in &CALLOUT_IDS {
        let id = id.swap(0, Ordering::AcqRel);
        if id != 0 {
            // SAFETY: a registered callout, whose filters went with the session.
            let _ = unsafe { sys::FwpsCalloutUnregisterById0(id) };
        }
    }
}

/// Adds the WFP filters of a handle (NETWORK, NETWORK_FORWARD, FLOW or SOCKET), and makes it
/// findable by the hooks.
///
/// # Safety
///
/// At PASSIVE_LEVEL.
pub unsafe fn attach(open: &Arc<Open>) -> Result<(), sys::NTSTATUS> {
    let engine = ENGINE.load(Ordering::Acquire);
    if engine.is_null() {
        return Err(sys::STATUS_INVALID_DEVICE_STATE);
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    open.id.store(id, Ordering::Release);
    HANDLES.lock().insert(id, open.clone());
    // Higher priorities run first: weights 1 to 60,001.
    let mut weight = (i32::from(open.priority) + 30_001) as u64;
    for i in 0..CALLOUTS {
        let h = callout(i);
        if h.avulse != open.layer {
            continue;
        }
        let mut filter = sys::FWPM_FILTER0 {
            displayData: sys::FWPM_DISPLAY_DATA0 {
                name: w!("avulse").as_ptr().cast_mut(),
                description: null_mut(),
            },
            layerKey: h.layer,
            subLayerKey: SUBLAYER,
            ..Default::default()
        };
        // The context, in a union with `providerContextKey` (no FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT).
        filter.__bindgen_anon_1.rawContext = id;
        filter.weight.type_ = sys::FWP_DATA_TYPE_::FWP_UINT64;
        filter.weight.__bindgen_anon_1.uint64 = &mut weight;
        filter.action.type_ = if h.inspect {
            sys::FWP_ACTION_CALLOUT_INSPECTION
        } else {
            sys::FWP_ACTION_CALLOUT_UNKNOWN
        };
        filter.action.__bindgen_anon_1.calloutKey = callout_key(i as u8);
        let mut filter_id = 0;
        // SAFETY: the engine is open; `filter` and `weight` are valid for the call.
        let status = unsafe { sys::FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
        if status != sys::STATUS_SUCCESS {
            // SAFETY: at PASSIVE_LEVEL.
            unsafe { detach(open) };
            return Err(status);
        }
        open.filters.lock().push(filter_id);
    }
    Ok(())
}

/// Removes a handle's filters, and from the hooks' table. A classify in progress keeps its own
/// reference to the handle.
///
/// # Safety
///
/// At PASSIVE_LEVEL.
pub unsafe fn detach(open: &Open) {
    let last_flow = {
        let mut handles = HANDLES.lock();
        handles.remove(&open.id.load(Ordering::Acquire));
        open.layer == Layer::Flow && !handles.values().any(|h| h.layer == Layer::Flow)
    };
    let ids: Vec<u64> = core::mem::take(&mut *open.filters.lock());
    let engine = ENGINE.load(Ordering::Acquire);
    if !engine.is_null() {
        for id in ids {
            // SAFETY: the engine is open, and `id` is a filter it added.
            let _ = unsafe { sys::FwpmFilterDeleteById0(engine, id) };
        }
    }
    if last_flow {
        // No FLOW handle is left to report the end of the flows seen.
        // SAFETY: at PASSIVE_LEVEL.
        unsafe { ale::forget_flows() };
    }
}

/// The open handle of id `id` (a WFP filter's context), if it is still open.
pub fn handle(id: u64) -> Option<Arc<Open>> {
    HANDLES.lock().get(&id).cloned()
}

/// The open handles at `layer`; none if the list could not be allocated.
pub fn handles_at(layer: Layer) -> Vec<Arc<Open>> {
    let handles = HANDLES.lock();
    let at = || handles.values().filter(|h| h.layer == layer);
    let mut v = Vec::new();
    if v.try_reserve_exact(at().count()).is_ok() {
        v.extend(at().cloned());
    }
    v
}

unsafe extern "C" fn notify(
    _kind: sys::FWPS_CALLOUT_NOTIFY_TYPE,
    _filter_key: *const sys::GUID,
    _filter: *mut sys::FWPS_FILTER3,
) -> sys::NTSTATUS {
    sys::STATUS_SUCCESS
}

macro_rules! classify_fns {
    ($($name:ident = $i:expr;)*) => {$(
        unsafe extern "C" fn $name(
            values: *const sys::FWPS_INCOMING_VALUES0,
            meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
            layer_data: *mut c_void,
            _context: *const c_void,
            filter: *const sys::FWPS_FILTER3,
            _flow: u64,
            out: *mut sys::FWPS_CLASSIFY_OUT0,
        ) {
            // SAFETY: WFP passes valid pointers.
            unsafe { classify(&HOOKS[$i], values, meta, layer_data, filter, out) }
        }
    )*};
}

classify_fns! {
    classify_0 = 0;
    classify_1 = 1;
    classify_2 = 2;
    classify_3 = 3;
    classify_4 = 4;
    classify_5 = 5;
}

/// The 32-bit incoming value at `index`, or 0.
///
/// # Safety
///
/// `values` is what WFP passed.
pub unsafe fn value_u32(values: *const sys::FWPS_INCOMING_VALUES0, index: usize) -> u32 {
    // SAFETY: as above; the index is checked against the count.
    unsafe {
        let v = &*values;
        if index >= v.valueCount as usize {
            return 0;
        }
        (*v.incomingValue.add(index)).value.__bindgen_anon_1.uint32
    }
}

/// Now, in nanoseconds of `QueryPerformanceCounter`.
pub fn now_ns() -> i64 {
    // SAFETY: plain call.
    let ticks = unsafe { sys::KeQueryPerformanceCounter(null_mut()) };
    // SAFETY: a LARGE_INTEGER.
    let ticks = unsafe { ticks.QuadPart } as u128;
    let freq = u128::from(FREQUENCY.load(Ordering::Relaxed).max(1));
    (ticks * 1_000_000_000 / freq) as i64
}

/// Runs the handle the filter belongs to on the packet: diverts, copies or drops it if it
/// matches, else lets the next filter decide.
unsafe fn classify(
    hook: &Hook,
    values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    filter: *const sys::FWPS_FILTER3,
    out: *mut sys::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP passes a valid `out`.
    let out = unsafe { &mut *out };
    out.actionType = sys::FWP_ACTION_CONTINUE;
    if out.rights & sys::FWPS_RIGHT_ACTION_WRITE == 0 || layer_data.is_null() {
        return;
    }
    // SAFETY: WFP passes a valid filter.
    let id = unsafe { (*filter).context };
    let Some(open) = handle(id) else {
        return;
    };
    if open.idle() {
        return;
    }
    let nbl = layer_data.cast::<sys::NET_BUFFER_LIST>();
    // A packet sent by a handle of this priority or a lower one passes this handle by: it saw the
    // packet before the sender did (or is the sender). Handles of lower priorities see it as an
    // impostor, as on Linux.
    // SAFETY: at these layers, `layer_data` is a NET_BUFFER_LIST.
    let impostor = match unsafe { inject::sender(nbl, hook.ipv6) } {
        Some(p) if open.priority >= p => return,
        Some(_) => true,
        None => false,
    };
    // SAFETY: WFP passes valid values.
    let flags = unsafe { value_u32(values, hook.flags) };
    let loopback = flags & sys::FWP_CONDITION_FLAG_IS_LOOPBACK != 0;
    // Loopback packets are seen once, outbound, as in WinDivert.
    if loopback && !hook.outbound && hook.avulse == Layer::Network {
        return;
    }
    // SAFETY: as above.
    let if_idx = unsafe { value_u32(values, hook.if_idx) };
    if !open.captures_on(if_idx) {
        return;
    }
    // SAFETY: as above.
    let nb = unsafe { sys::nbl_first_nb(nbl) };
    // Inbound, the data starts after the IP header: move back to include it.
    let back = if hook.outbound {
        0
    } else {
        // SAFETY: WFP passes valid metadata.
        let m = unsafe { &*meta };
        if m.currentMetadataValues & sys::FWPS_METADATA_FIELD_IP_HEADER_SIZE == 0 {
            return;
        }
        m.ipHeaderSize
    };
    if back > 0 {
        // SAFETY: the IP header precedes the data in the same buffer.
        let status = unsafe { sys::NdisRetreatNetBufferDataStart(nb, back, 0, None) };
        if status != sys::NDIS_STATUS_SUCCESS {
            return;
        }
    }
    let mut addr = Address::new(hook.avulse);
    addr.timestamp = now_ns();
    addr.outbound = hook.outbound;
    addr.loopback = loopback;
    addr.ipv6 = hook.ipv6;
    addr.impostor = impostor;
    addr.if_idx = if_idx;
    // SAFETY: WFP passes valid values.
    addr.sub_if_idx = unsafe { value_u32(values, hook.sub_if_idx) };
    let sniff = open.flags.contains(Flags::SNIFF);
    let drop = open.flags.contains(Flags::DROP);
    let mut m: Meta<'_> = addr.meta();
    m.priority = open.priority;
    // SAFETY: `nb` is valid, at DISPATCH_LEVEL or below.
    let result = unsafe { eval::evaluate_nb(open.program(), nb, Link::Ip, &m, !drop) };
    if back > 0 {
        // SAFETY: undoes the retreat above.
        unsafe { sys::NdisAdvanceNetBufferDataStart(nb, back, 0, None) };
    }
    let Some((true, copy)) = result else {
        return;
    };
    match copy {
        _ if drop => open.mutable.lock().stats.dropped += 1,
        eval::Copied::Data(data) => {
            addr.sniffed = sniff;
            open.deliver(addr, data);
        }
        // Fail open: the packet goes on, uncopied.
        eval::Copied::Failed | eval::Copied::None => {
            open.mutable.lock().stats.load_errors += 1;
            return;
        }
    }
    if sniff {
        return;
    }
    // Diverted (taken by user mode) or dropped: the original goes no further.
    out.actionType = sys::FWP_ACTION_BLOCK;
    out.rights &= !sys::FWPS_RIGHT_ACTION_WRITE;
    if !drop {
        out.flags |= sys::FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
}
