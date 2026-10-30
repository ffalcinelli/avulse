//! The WFP side: callouts at the inbound and outbound IPv4 packet layers, added to the base
//! filtering engine in a dynamic session, so that closing the session removes the sublayer,
//! the callouts and the filters.

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use avulse_filter::{Layer, Meta};
use avulse_proto::Link;

use crate::stats::{self, Counter};
use crate::{programs, sys, w};

const SUBLAYER: sys::GUID = guid(
    0x5e1a_7c3d,
    0x0b2f,
    0x4e6a,
    [0x9c, 0x41, 0x2d, 0x8e, 0x6f, 0x13, 0xa5, 0x70],
);
const CALLOUT_IN: sys::GUID = guid(
    0x5e1a_7c3d,
    0x0b2f,
    0x4e6a,
    [0x9c, 0x41, 0x2d, 0x8e, 0x6f, 0x13, 0xa5, 0x71],
);
const CALLOUT_OUT: sys::GUID = guid(
    0x5e1a_7c3d,
    0x0b2f,
    0x4e6a,
    [0x9c, 0x41, 0x2d, 0x8e, 0x6f, 0x13, 0xa5, 0x72],
);

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> sys::GUID {
    sys::GUID {
        Data1: a,
        Data2: b,
        Data3: c,
        Data4: d,
    }
}

static DEVICE: AtomicPtr<sys::DEVICE_OBJECT> = AtomicPtr::new(null_mut());
static ENGINE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CALLOUT_IDS: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

/// Registers the callouts and adds them, with their filters, to the engine.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, with the driver object.
pub(crate) unsafe fn register(driver: *mut sys::DRIVER_OBJECT) -> sys::NTSTATUS {
    let mut device = null_mut();
    // SAFETY: an unnamed device, which FwpsCalloutRegister needs.
    let status = unsafe {
        sys::IoCreateDevice(
            driver,
            0,
            null_mut(),
            sys::FILE_DEVICE_NETWORK,
            sys::FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device,
        )
    };
    if status != 0 {
        return status;
    }
    DEVICE.store(device, Ordering::Release);

    for (i, key) in [CALLOUT_IN, CALLOUT_OUT].into_iter().enumerate() {
        let callout = sys::FWPS_CALLOUT3 {
            calloutKey: key,
            flags: 0,
            classifyFn: Some(if i == 0 { classify_in } else { classify_out }),
            notifyFn: Some(notify),
            flowDeleteFn: None,
        };
        let mut id = 0;
        // SAFETY: `device` is ours; `callout` is valid for the call.
        let status = unsafe { sys::FwpsCalloutRegister3(device.cast(), &callout, &mut id) };
        if status != 0 {
            return status;
        }
        CALLOUT_IDS[i].store(id, Ordering::Release);
    }

    let mut session = sys::FWPM_SESSION0 {
        flags: sys::FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut engine = null_mut();
    // SAFETY: a local engine session, valid arguments.
    let status = unsafe {
        sys::FwpmEngineOpen0(
            null(),
            sys::RPC_C_AUTHN_WINNT,
            null_mut(),
            &mut session,
            &mut engine,
        )
    };
    if status != 0 {
        return status;
    }
    ENGINE.store(engine, Ordering::Release);
    // SAFETY: `engine` is open.
    let status = unsafe { add_objects(engine) };
    if status != 0 {
        // SAFETY: `engine` is open.
        let _ = unsafe { sys::FwpmTransactionAbort0(engine) };
    }
    status
}

/// The sublayer, callouts and filters, in one transaction.
unsafe fn add_objects(engine: sys::HANDLE) -> sys::NTSTATUS {
    macro_rules! check {
        ($e:expr) => {{
            // SAFETY: `engine` is open and every pointer argument is valid for the call.
            let status = unsafe { $e };
            if status != 0 {
                return status;
            }
        }};
    }
    check!(sys::FwpmTransactionBegin0(engine, 0));
    let mut sublayer = sys::FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER,
        displayData: sys::FWPM_DISPLAY_DATA0 {
            name: w!("Avulse spike").as_ptr().cast_mut(),
            description: null_mut(),
        },
        weight: 0x8000,
        ..Default::default()
    };
    check!(sys::FwpmSubLayerAdd0(engine, &mut sublayer, null_mut()));
    let layers = [
        (CALLOUT_IN, sys::LAYER_INBOUND_IPPACKET_V4),
        (CALLOUT_OUT, sys::LAYER_OUTBOUND_IPPACKET_V4),
    ];
    for (key, layer) in layers {
        let mut callout = sys::FWPM_CALLOUT0 {
            calloutKey: key,
            displayData: sys::FWPM_DISPLAY_DATA0 {
                name: w!("Avulse spike callout").as_ptr().cast_mut(),
                description: null_mut(),
            },
            applicableLayer: layer,
            ..Default::default()
        };
        check!(sys::FwpmCalloutAdd0(
            engine,
            &mut callout,
            null_mut(),
            null_mut()
        ));
        let mut filter = sys::FWPM_FILTER0 {
            displayData: sys::FWPM_DISPLAY_DATA0 {
                name: w!("Avulse spike filter").as_ptr().cast_mut(),
                description: null_mut(),
            },
            layerKey: layer,
            subLayerKey: SUBLAYER,
            ..Default::default()
        };
        filter.action.type_ = sys::FWP_ACTION_CALLOUT_UNKNOWN;
        filter.action.__bindgen_anon_1.calloutKey = key;
        check!(sys::FwpmFilterAdd0(
            engine,
            &mut filter,
            null_mut(),
            null_mut()
        ));
    }
    check!(sys::FwpmTransactionCommit0(engine));
    0
}

/// Removes the objects (by closing the dynamic session) and the callouts.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once.
pub(crate) unsafe fn unregister() {
    let engine = ENGINE.swap(null_mut(), Ordering::AcqRel);
    if !engine.is_null() {
        // SAFETY: `engine` is open.
        let _ = unsafe { sys::FwpmEngineClose0(engine) };
    }
    for id in &CALLOUT_IDS {
        let id = id.swap(0, Ordering::AcqRel);
        if id != 0 {
            // SAFETY: `id` is a registered callout; its filters are gone with the session.
            let status = unsafe { sys::FwpsCalloutUnregisterById0(id) };
            if status != 0 {
                wdk::println!("avulse_spike: FwpsCalloutUnregisterById0: {status:#x}");
            }
        }
    }
    let device = DEVICE.swap(null_mut(), Ordering::AcqRel);
    if !device.is_null() {
        // SAFETY: the callouts that used it are unregistered.
        unsafe { sys::IoDeleteDevice(device) };
    }
}

unsafe extern "C" fn notify(
    _kind: sys::FWPS_CALLOUT_NOTIFY_TYPE,
    _filter_key: *const sys::GUID,
    _filter: *mut sys::FWPS_FILTER3,
) -> sys::NTSTATUS {
    0
}

unsafe extern "C" fn classify_in(
    _values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    _context: *const c_void,
    _filter: *const sys::FWPS_FILTER3,
    _flow: u64,
    out: *mut sys::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP passes valid pointers.
    unsafe { classify(false, meta, layer_data, out) }
}

unsafe extern "C" fn classify_out(
    _values: *const sys::FWPS_INCOMING_VALUES0,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    _context: *const c_void,
    _filter: *const sys::FWPS_FILTER3,
    _flow: u64,
    out: *mut sys::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP passes valid pointers.
    unsafe { classify(true, meta, layer_data, out) }
}

/// Blocks the packet if the program matches it, else lets the next filter decide.
unsafe fn classify(
    outbound: bool,
    meta: *const sys::FWPS_INCOMING_METADATA_VALUES0,
    layer_data: *mut c_void,
    out: *mut sys::FWPS_CLASSIFY_OUT0,
) {
    // SAFETY: WFP passes a valid `out`.
    let out = unsafe { &mut *out };
    out.actionType = sys::FWP_ACTION_CONTINUE;
    let (Some(p), false) = (programs(), layer_data.is_null()) else {
        return;
    };
    stats::add(
        if outbound {
            Counter::WfpOutbound
        } else {
            Counter::WfpInbound
        },
        1,
    );
    let nbl = layer_data.cast::<sys::NET_BUFFER_LIST>();
    // SAFETY: at the IP packet layers, `layer_data` is a NET_BUFFER_LIST.
    let nb = unsafe { sys::nbl_first_nb(nbl) };
    // Inbound, the data starts after the IP header: move back to include it.
    let back = if outbound {
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
    let m = Meta {
        layer: Layer::Network,
        outbound,
        ..Meta::default()
    };
    // SAFETY: `nb` is valid, at DISPATCH_LEVEL or below.
    let matched = unsafe { stats::evaluate(&p.wfp, nb, Link::Ip, &m) };
    if back > 0 {
        // SAFETY: undoes the retreat above.
        unsafe { sys::NdisAdvanceNetBufferDataStart(nb, back, 0, None) };
    }
    if matched == Some(true) {
        stats::add(Counter::WfpMatched, 1);
        if out.rights & sys::FWPS_RIGHT_ACTION_WRITE != 0 {
            out.actionType = sys::FWP_ACTION_BLOCK;
            out.rights &= !sys::FWPS_RIGHT_ACTION_WRITE;
            stats::add(Counter::WfpBlocked, 1);
        }
    }
}
