//! The ETHERNET layer: an NDIS lightweight filter, a modifying filter on Ethernet adapters,
//! installed with `avulse.inf` (`netcfg -l avulse.inf -c s -i avulse`). Without that install,
//! registering fails, the other layers keep working, and ETHERNET handles are refused.
//!
//! The filter has one module per adapter. Each frame of a module's send and receive paths goes
//! through the open ETHERNET handles, highest priority first (`process`): a handle that sniffs
//! gets a copy, one that diverts or drops takes the frame, and the frame goes on if none took it.
//! The decision is per NET_BUFFER; a NET_BUFFER_LIST whose frames all go on passes untouched,
//! otherwise the filter completes (or returns) it and sends on copies of the frames that went on.
//!
//! The filter injects frames through NET_BUFFER_LISTs from its own pool, which its completion
//! handlers recognise and free. A filter's own sends and indications never pass through its own
//! handlers, so `process` runs an injected frame through the handles of lower priority than the
//! sender's first, as impostors: Linux's mark rule, inside the module.
//!
//! What the network card was to do with a frame comes out of band, and the address's context
//! keeps it ([`EthernetContext`]): a VLAN tag the card inserts or removed (put back into the frame
//! the handles see, and taken out again when the frame is reinjected), and large sends (LSO),
//! which the card segments.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use avulse_abi::ioctl::EthernetContext;
use avulse_abi::{Address, Flags};
use avulse_filter::{Layer, Meta};
use avulse_proto::{Link, Packet, checksum};

use crate::handle::Open;
use crate::lock::SpinLock;
use crate::sys::{self, unicode, w};
use crate::{eval, wfp};

/// `NDIS_*_FLAGS_*` values, as `ndis.h` defines them.
const SEND_DISPATCH: u32 = 1;
const SEND_COMPLETE_DISPATCH: u32 = 1;
const RECEIVE_DISPATCH: u32 = 1;
const RECEIVE_RESOURCES: u32 = 2;
const RETURN_DISPATCH: u32 = 1;
/// `NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE` (V1 is 0).
const LSO_V2_TYPE: usize = 1;
/// A pool tag, `avlE`.
const TAG: u32 = u32::from_le_bytes(*b"avlE");

static DRIVER_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static POOL: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
/// The attached modules, which injection finds by interface index.
static MODULES: SpinLock<Vec<Arc<Module>>> = SpinLock::new(Vec::new());
/// The open ETHERNET handles, highest priority first, as a snapshot that the frame paths clone.
static HANDLES: SpinLock<Option<Arc<[Arc<Open>]>>> = SpinLock::new(None);

/// One filter module: the filter on one adapter.
struct Module {
    handle: sys::NDIS_HANDLE,
    /// The adapter's interface index, as IP Helper and WFP number it.
    if_idx: u32,
    state: SpinLock<State>,
}

// SAFETY: the NDIS handle may be used from any thread; the rest is behind a lock.
unsafe impl Send for Module {}
// SAFETY: as above.
unsafe impl Sync for Module {}

/// A module's state: whether it may send and indicate, and how many of its own sends and
/// indications are still out, which a pause waits for.
#[derive(Default)]
struct State {
    running: bool,
    outstanding: usize,
    pausing: bool,
}

impl Module {
    /// Counts `n` of the module's own sends or indications. False (nothing counted) unless it
    /// is running.
    fn enter(&self, n: usize) -> bool {
        let mut s = self.state.lock();
        if !s.running {
            return false;
        }
        s.outstanding += n;
        true
    }

    /// One of the module's own sends or indications came back: completes a pause waiting for
    /// it.
    fn leave(&self) {
        let done = {
            let mut s = self.state.lock();
            s.outstanding -= 1;
            let done = s.pausing && s.outstanding == 0;
            if done {
                s.pausing = false;
            }
            done
        };
        if done {
            // SAFETY: the module's handle, pausing.
            unsafe { sys::NdisFPauseComplete(self.handle) };
        }
    }
}

/// Whether the filter is registered: the driver was installed as one.
pub fn available() -> bool {
    !DRIVER_HANDLE.load(Ordering::Acquire).is_null()
}

/// Registers the filter driver and allocates its pool. The `UniqueName` and `ServiceName` must
/// match the INF.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, with the driver object.
pub unsafe fn register(driver: *mut sys::DRIVER_OBJECT) -> sys::NDIS_STATUS {
    let mut chars = sys::NDIS_FILTER_DRIVER_CHARACTERISTICS::default();
    chars.Header.Type = sys::NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS as u8;
    chars.Header.Revision = sys::NDIS_FILTER_CHARACTERISTICS_REVISION_2 as u8;
    chars.Header.Size = (core::mem::offset_of!(
        sys::NDIS_FILTER_DRIVER_CHARACTERISTICS,
        CancelDirectOidRequestHandler
    ) + size_of::<sys::FILTER_CANCEL_DIRECT_OID_REQUEST_HANDLER>()) as u16;
    chars.MajorNdisVersion = 6;
    chars.MinorNdisVersion = 30;
    chars.MajorDriverVersion = 0;
    chars.MinorDriverVersion = 1;
    chars.FriendlyName = unicode(w!("Avulse packet filter"));
    chars.UniqueName = unicode(w!("{3c1d6e52-8b7a-4f19-a2d4-5e9b0c71f846}"));
    chars.ServiceName = unicode(w!("avulse"));
    chars.AttachHandler = Some(attach_module);
    chars.DetachHandler = Some(detach_module);
    chars.RestartHandler = Some(restart);
    chars.PauseHandler = Some(pause);
    chars.SendNetBufferListsHandler = Some(send_nbls);
    chars.SendNetBufferListsCompleteHandler = Some(send_complete);
    chars.ReceiveNetBufferListsHandler = Some(receive);
    chars.ReturnNetBufferListsHandler = Some(return_nbls);
    let mut handle = null_mut();
    // SAFETY: valid driver object and characteristics.
    let status =
        unsafe { sys::NdisFRegisterFilterDriver(driver, driver.cast(), &mut chars, &mut handle) };
    if status != sys::NDIS_STATUS_SUCCESS {
        return status;
    }
    // SAFETY: all zeros, then the header and fields NDIS reads.
    let mut params: sys::NET_BUFFER_LIST_POOL_PARAMETERS = unsafe { core::mem::zeroed() };
    params.Header.Type = sys::NDIS_OBJECT_TYPE_DEFAULT as u8;
    params.Header.Revision = sys::NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 as u8;
    params.Header.Size = size_of::<sys::NET_BUFFER_LIST_POOL_PARAMETERS>() as u16;
    params.fAllocateNetBuffer = 1;
    params.PoolTag = TAG;
    // SAFETY: the filter driver's handle and valid parameters.
    let pool = unsafe { sys::NdisAllocateNetBufferListPool(handle, &params) };
    if pool.is_null() {
        // SAFETY: registered above; no module is attached before `DriverEntry` returns.
        unsafe { sys::NdisFDeregisterFilterDriver(handle) };
        return sys::NDIS_STATUS_RESOURCES;
    }
    POOL.store(pool, Ordering::Release);
    DRIVER_HANDLE.store(handle, Ordering::Release);
    sys::NDIS_STATUS_SUCCESS
}

/// Detaches every module, deregisters the filter driver and frees the pool.
///
/// # Safety
///
/// At PASSIVE_LEVEL, at unload, before the scratch is freed.
pub unsafe fn unregister() {
    let handle = DRIVER_HANDLE.swap(null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        // SAFETY: registered by `register`; this waits for every module to pause and detach,
        // and so for every frame the filter sent or indicated to come back.
        unsafe { sys::NdisFDeregisterFilterDriver(handle) };
    }
    let pool = POOL.swap(null_mut(), Ordering::AcqRel);
    if !pool.is_null() {
        // SAFETY: the pool `register` allocated, whose lists all came back.
        unsafe { sys::NdisFreeNetBufferListPool(pool) };
    }
    // Free the tables' allocations, or Driver Verifier reports them as leaked.
    drop(core::mem::take(&mut *MODULES.lock()));
    drop(HANDLES.lock().take());
}

/// Adds an ETHERNET handle to those the modules run, after the ones of its priority or higher.
pub fn attach(open: &Arc<Open>) {
    let mut handles = HANDLES.lock();
    let old: &[Arc<Open>] = handles.as_deref().unwrap_or(&[]);
    let at = old.partition_point(|h| h.priority >= open.priority);
    let mut new = Vec::with_capacity(old.len() + 1);
    new.extend_from_slice(&old[..at]);
    new.push(open.clone());
    new.extend_from_slice(&old[at..]);
    let old = handles.replace(new.into());
    drop(handles);
    drop(old);
}

/// Removes a handle from those the modules run. A frame in progress keeps its own snapshot.
pub fn detach(open: &Arc<Open>) {
    if open.layer != Layer::Ethernet {
        return;
    }
    let mut handles = HANDLES.lock();
    let Some(old) = handles.as_deref() else {
        return;
    };
    let new: Vec<Arc<Open>> = old
        .iter()
        .filter(|h| !Arc::ptr_eq(h, open))
        .cloned()
        .collect();
    let old = if new.is_empty() {
        handles.take()
    } else {
        handles.replace(new.into())
    };
    drop(handles);
    drop(old);
}

fn snapshot() -> Option<Arc<[Arc<Open>]>> {
    HANDLES.lock().clone()
}

fn module<'a>(context: sys::NDIS_HANDLE) -> &'a Module {
    // SAFETY: the context `attach_module` set, alive until `detach_module`, after which NDIS calls
    // nothing else on the module.
    unsafe { &*context.cast::<Module>() }
}

unsafe extern "C" fn attach_module(
    filter_handle: sys::NDIS_HANDLE,
    _driver_context: sys::NDIS_HANDLE,
    params: sys::PNDIS_FILTER_ATTACH_PARAMETERS,
) -> sys::NDIS_STATUS {
    // SAFETY: NDIS passes valid parameters.
    let p = unsafe { &*params };
    // NdisMedium802_3: the INF binds the filter to Ethernet adapters only.
    if p.MiniportMediaType as u32 != 0 {
        return sys::NDIS_STATUS_NOT_SUPPORTED;
    }
    let module = Arc::new(Module {
        handle: filter_handle,
        if_idx: p.BaseMiniportIfIndex,
        state: SpinLock::new(State::default()),
    });
    let context = Arc::into_raw(module.clone()).cast_mut();
    let mut attrs = sys::NDIS_FILTER_ATTRIBUTES::default();
    attrs.Header.Type = sys::NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES as u8;
    attrs.Header.Revision = sys::NDIS_FILTER_ATTRIBUTES_REVISION_1 as u8;
    attrs.Header.Size = size_of::<sys::NDIS_FILTER_ATTRIBUTES>() as u16;
    // SAFETY: called during attach, with NDIS's handle.
    let status = unsafe { sys::NdisFSetAttributes(filter_handle, context.cast(), &mut attrs) };
    if status != sys::NDIS_STATUS_SUCCESS {
        // SAFETY: from `Arc::into_raw` above, not shared.
        drop(unsafe { Arc::from_raw(context) });
        return status;
    }
    // The module starts paused; `restart` lets it run.
    MODULES.lock().push(module);
    sys::NDIS_STATUS_SUCCESS
}

unsafe extern "C" fn detach_module(context: sys::NDIS_HANDLE) {
    let ptr = context.cast::<Module>().cast_const();
    let removed = {
        let mut modules = MODULES.lock();
        let i = modules.iter().position(|m| Arc::as_ptr(m) == ptr);
        i.map(|i| modules.swap_remove(i))
    };
    drop(removed);
    // SAFETY: the reference `attach_module` leaked as the context; NDIS calls nothing else on the
    // module after detach.
    drop(unsafe { Arc::from_raw(ptr) });
}

unsafe extern "C" fn restart(
    context: sys::NDIS_HANDLE,
    _params: sys::PNDIS_FILTER_RESTART_PARAMETERS,
) -> sys::NDIS_STATUS {
    let mut s = module(context).state.lock();
    s.running = true;
    s.pausing = false;
    sys::NDIS_STATUS_SUCCESS
}

unsafe extern "C" fn pause(
    context: sys::NDIS_HANDLE,
    _params: sys::PNDIS_FILTER_PAUSE_PARAMETERS,
) -> sys::NDIS_STATUS {
    let mut s = module(context).state.lock();
    s.running = false;
    if s.outstanding == 0 {
        return sys::NDIS_STATUS_SUCCESS;
    }
    // The last of the module's own frames to come back completes the pause (`Module::leave`).
    s.pausing = true;
    sys::NDIS_STATUS_PENDING
}

/// What the network card was asked to do with a NET_BUFFER_LIST's frames.
#[derive(Clone, Copy, Default)]
struct Oob {
    /// The 802.1Q tag control information, if the tag is out of band.
    tag: Option<u16>,
    /// The large send request (`TcpLargeSendNetBufferListInfo`), on the send path.
    lso: usize,
}

impl Oob {
    /// # Safety
    ///
    /// `nbl` is a valid NET_BUFFER_LIST.
    unsafe fn of(nbl: *mut sys::NET_BUFFER_LIST, outbound: bool) -> Oob {
        // SAFETY: the caller's contract.
        let (q, lso) = unsafe {
            (
                sys::nbl_info(nbl, sys::IEEE_8021Q_INFO),
                sys::nbl_info(nbl, sys::TCP_LARGE_SEND_INFO),
            )
        };
        // NDIS_NET_BUFFER_LIST_8021Q_INFO: UserPriority:3, CanonicalFormatId:1, VlanId:12.
        let (prio, cfi, vid) = (q & 7, (q >> 3) & 1, (q >> 4) & 0xfff);
        Oob {
            tag: (prio != 0 || vid != 0).then_some(((prio << 13) | (cfi << 12) | vid) as u16),
            // On the receive path the same slot holds TcpReceiveNoPush.
            lso: if outbound { lso } else { 0 },
        }
    }

    /// The segment size of a large send (MSS:20 in both versions), or 0.
    fn mss(&self) -> u32 {
        (self.lso & 0xf_ffff) as u32
    }

    fn lso_v2(&self) -> bool {
        (self.lso >> 30) & 3 == LSO_V2_TYPE
    }

    /// What the address's context keeps of this, on the adapter `if_idx`; empty if nothing.
    fn context(&self, if_idx: u32) -> avulse_abi::Context {
        let mut flags = 0;
        if self.tag.is_some() {
            flags |= EthernetContext::VLAN_OFFLOADED;
        }
        if self.mss() != 0 {
            flags |= if self.lso_v2() {
                EthernetContext::LSO_V2
            } else {
                EthernetContext::LSO_V1
            };
        }
        if flags == 0 {
            return avulse_abi::Context::EMPTY;
        }
        EthernetContext {
            if_idx,
            flags,
            lso_mss: self.mss(),
        }
        .encode()
    }
}

/// What became of a frame.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// It goes on.
    Pass,
    /// A handle diverted or dropped it.
    Taken,
}

/// The address of a frame of `module`, before the handle's own fields.
fn address(bytes: &[u8], module: &Module, outbound: bool, oob: &Oob) -> Address {
    let mut a = Address::new(Layer::Ethernet);
    a.timestamp = wfp::now_ns();
    a.outbound = outbound;
    a.if_idx = module.if_idx;
    // The tags, then the type of what they carry.
    let mut at = 12;
    while let Some(&[hi, lo, t0, t1]) = bytes.get(at..at + 4) {
        if !matches!([hi, lo], [0x81, 0x00] | [0x88, 0xa8] | [0x91, 0x00]) {
            break;
        }
        if at == 12 {
            a.vlan = true;
            a.vlan_tci = u16::from_be_bytes([t0, t1]);
        }
        at += 4;
    }
    a.ipv6 = bytes.get(at..at + 2) == Some(&[0x86, 0xdd]);
    let valid = checksum::verify(bytes, Link::Ethernet);
    a.ip_checksum = valid.ipv4;
    a.tcp_checksum = valid.tcp;
    a.udp_checksum = valid.udp;
    a.context = oob.context(module.if_idx);
    a
}

/// Runs the handles on the frame of `nb`, highest priority first. With `below`, the frame was
/// injected by a handle of that priority: only lower ones see it, as an impostor. Also returns
/// the length of the frame's TCP payload, for the completion of an LSOv1 send.
///
/// # Safety
///
/// `nb` is a valid NET_BUFFER, at IRQL <= DISPATCH_LEVEL.
unsafe fn process(
    handles: &[Arc<Open>],
    module: &Module,
    nb: *mut sys::NET_BUFFER,
    oob: &Oob,
    outbound: bool,
    below: Option<i16>,
) -> (Fate, u32) {
    let run = |frame: &eval::Frame<'_>| {
        let bytes = frame.bytes;
        let payload = if oob.mss() != 0 {
            Packet::parse(bytes, Link::Ethernet).payload().len() as u32
        } else {
            0
        };
        let base = address(bytes, module, outbound, oob);
        for open in handles {
            if open.idle() || !open.captures_on(module.if_idx) {
                continue;
            }
            let impostor = match below {
                Some(p) if open.priority >= p => continue,
                Some(_) => true,
                None => false,
            };
            let mut addr = base;
            addr.impostor = impostor;
            let mut m: Meta<'_> = addr.meta();
            m.priority = open.priority;
            m.hash = frame.hash;
            // Fail open: a frame that could not be evaluated goes on.
            if frame.matches(open.program(), Link::Ethernet, &m) != Some(true) {
                continue;
            }
            if open.flags.contains(Flags::DROP) {
                open.mutable.lock().stats.dropped += 1;
                return (Fate::Taken, payload);
            }
            addr.sniffed = open.flags.contains(Flags::SNIFF);
            let Some(data) = sys::try_copy(bytes) else {
                // Fail open: the frame goes on, uncopied.
                open.mutable.lock().stats.load_errors += 1;
                continue;
            };
            open.deliver(addr, data);
            if !addr.sniffed {
                return (Fate::Taken, payload);
            }
        }
        (Fate::Pass, payload)
    };
    // SAFETY: the caller's contract.
    unsafe { eval::with_frame(nb, oob.tag, run) }.unwrap_or((Fate::Pass, 0))
}

/// Allocates one of the filter's own NET_BUFFER_LISTs, holding a copy of `data`, for `module`.
/// Its MDL describes the copy, which is how [`free_own`] finds it again.
fn alloc_own(module: &Module, data: Box<[u8]>) -> Option<*mut sys::NET_BUFFER_LIST> {
    let pool = POOL.load(Ordering::Acquire);
    if pool.is_null() || data.is_empty() {
        return None;
    }
    let len = data.len();
    let data = Box::into_raw(data);
    let free = |data| {
        // SAFETY: from `Box::into_raw` above, unused.
        drop(unsafe { Box::from_raw(data) })
    };
    // SAFETY: a nonpaged buffer of `len` bytes, which lives until `free_own`.
    let mdl = unsafe { sys::IoAllocateMdl(data.cast(), len as u32, 0, 0, null_mut()) };
    if mdl.is_null() {
        free(data);
        return None;
    }
    // SAFETY: the MDL describes nonpaged memory.
    unsafe { sys::MmBuildMdlForNonPagedPool(mdl) };
    // SAFETY: a valid pool and MDL.
    let nbl = unsafe { sys::NdisAllocateNetBufferAndNetBufferList(pool, 0, 0, mdl, 0, len as _) };
    if nbl.is_null() {
        // SAFETY: allocated above, unused.
        unsafe { sys::IoFreeMdl(mdl) };
        free(data);
        return None;
    }
    // SAFETY: a fresh NBL the filter owns.
    unsafe { (*nbl).SourceHandle = module.handle };
    Some(nbl)
}

/// Whether `nbl` is one of the filter's own.
///
/// # Safety
///
/// `nbl` is a valid NET_BUFFER_LIST.
unsafe fn is_own(nbl: *mut sys::NET_BUFFER_LIST) -> bool {
    // SAFETY: the caller's contract.
    let pool = unsafe { (*nbl).NdisPoolHandle };
    !pool.is_null() && pool == POOL.load(Ordering::Acquire)
}

/// Frees one of the filter's own NET_BUFFER_LISTs, its MDL and its data.
///
/// # Safety
///
/// `nbl` came from `alloc_own` and is back with the filter.
unsafe fn free_own(nbl: *mut sys::NET_BUFFER_LIST) {
    // SAFETY: as above: one NET_BUFFER, whose MDL `alloc_own` built over the copy.
    unsafe {
        let mdl = sys::nb_first_mdl(sys::nbl_first_nb(nbl));
        sys::NdisFreeNetBufferList(nbl);
        let data = (*mdl).MappedSystemVa.cast::<u8>();
        let len = (*mdl).ByteCount as usize;
        sys::IoFreeMdl(mdl);
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
            data, len,
        )));
    }
}

/// A copy of the frame of `nb`, in one of the filter's own lists, with the out-of-band requests
/// of `from` (checksum offload, large send, VLAN tag).
///
/// # Safety
///
/// `nb` is a NET_BUFFER of `from`, both valid.
unsafe fn copy_nb(
    module: &Module,
    from: *mut sys::NET_BUFFER_LIST,
    nb: *mut sys::NET_BUFFER,
) -> Option<*mut sys::NET_BUFFER_LIST> {
    // SAFETY: the caller's contract.
    let len = unsafe { sys::nb_data_length(nb) } as usize;
    if len == 0 {
        return None;
    }
    let mut data = sys::try_zeroed(len)?;
    // SAFETY: `data` has room for `len` bytes; NDIS returns the data in place or copies it there.
    let p = unsafe { sys::NdisGetDataBuffer(nb, len as u32, data.as_mut_ptr().cast(), 1, 0) };
    if p.is_null() {
        return None;
    }
    if p.cast::<u8>() != data.as_mut_ptr() {
        // SAFETY: NDIS returned `len` readable bytes in place.
        data.copy_from_slice(unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) });
    }
    let nbl = alloc_own(module, data)?;
    for i in [
        sys::TCP_IP_CHECKSUM_INFO,
        sys::TCP_LARGE_SEND_INFO,
        sys::IEEE_8021Q_INFO,
    ] {
        // SAFETY: both lists are valid, and `nbl` is ours.
        unsafe { sys::set_nbl_info(nbl, i, sys::nbl_info(from, i)) };
    }
    Some(nbl)
}

/// A chain of NET_BUFFER_LISTs, built in order.
struct Chain {
    head: *mut sys::NET_BUFFER_LIST,
    tail: *mut sys::NET_BUFFER_LIST,
    len: u32,
}

impl Chain {
    fn new() -> Chain {
        Chain {
            head: null_mut(),
            tail: null_mut(),
            len: 0,
        }
    }

    /// # Safety
    ///
    /// `nbl` is a valid NET_BUFFER_LIST the caller owns, in no other chain.
    unsafe fn push(&mut self, nbl: *mut sys::NET_BUFFER_LIST) {
        // SAFETY: the caller's contract; `tail` is the last list pushed.
        unsafe {
            sys::set_nbl_next(nbl, null_mut());
            if self.tail.is_null() {
                self.head = nbl;
            } else {
                sys::set_nbl_next(self.tail, nbl);
            }
        }
        self.tail = nbl;
        self.len += 1;
    }

    /// # Safety
    ///
    /// The lists are valid and the caller owns them.
    unsafe fn append(&mut self, other: Chain) {
        let mut nbl = other.head;
        while !nbl.is_null() {
            // SAFETY: the caller's contract.
            let next = unsafe { sys::nbl_next(nbl) };
            // SAFETY: as above.
            unsafe { self.push(nbl) };
            nbl = next;
        }
    }
}

/// Runs the handles on every frame of `nbl`. Returns whether a handle took one, after copying
/// the frames that go on into `copies` (only then: when none was taken, `nbl` goes on as it is),
/// and the TCP payload of all its frames.
///
/// # Safety
///
/// `nbl` is a valid NET_BUFFER_LIST, at IRQL <= DISPATCH_LEVEL.
unsafe fn split(
    handles: &[Arc<Open>],
    module: &Module,
    nbl: *mut sys::NET_BUFFER_LIST,
    outbound: bool,
    copies: &mut Chain,
) -> (bool, u32) {
    // SAFETY: the caller's contract.
    let oob = unsafe { Oob::of(nbl, outbound) };
    let mut taken = false;
    let mut payload = 0;
    // SAFETY: as above.
    let first = unsafe { sys::nbl_first_nb(nbl) };
    let mut nb = first;
    while !nb.is_null() {
        // SAFETY: as above.
        let (fate, n) = unsafe { process(handles, module, nb, &oob, outbound, None) };
        payload += n;
        if fate == Fate::Taken && !taken {
            taken = true;
            // The frames before this one went on: copy them now.
            let mut earlier = first;
            while earlier != nb {
                // SAFETY: as above.
                unsafe {
                    if let Some(c) = copy_nb(module, nbl, earlier) {
                        copies.push(c);
                    }
                    earlier = sys::nb_next(earlier);
                }
            }
        } else if fate == Fate::Pass && taken {
            // SAFETY: as above.
            if let Some(c) = unsafe { copy_nb(module, nbl, nb) } {
                // SAFETY: a fresh list of ours.
                unsafe { copies.push(c) };
            }
        }
        // SAFETY: as above.
        nb = unsafe { sys::nb_next(nb) };
    }
    (taken, payload)
}

/// Counts `copies` as the module's own frames out, or frees them if it is not running. Returns
/// whether they may go.
///
/// # Safety
///
/// The copies are the filter's own lists.
unsafe fn admit(module: &Module, copies: &mut Chain) -> bool {
    if copies.len == 0 || module.enter(copies.len as usize) {
        return true;
    }
    let mut nbl = copies.head;
    while !nbl.is_null() {
        // SAFETY: the caller's contract.
        unsafe {
            let next = sys::nbl_next(nbl);
            free_own(nbl);
            nbl = next;
        }
    }
    *copies = Chain::new();
    false
}

unsafe extern "C" fn send_nbls(
    context: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    port: sys::NDIS_PORT_NUMBER,
    flags: u32,
) {
    let module = module(context);
    let Some(handles) = snapshot() else {
        // SAFETY: NDIS passes a valid chain, which goes on.
        unsafe { sys::NdisFSendNetBufferLists(module.handle, nbls, port, flags) };
        return;
    };
    let (mut pass, mut done, mut copies) = (Chain::new(), Chain::new(), Chain::new());
    let mut nbl = nbls;
    while !nbl.is_null() {
        // SAFETY: NDIS passes a valid chain, which the filter owns until it passes or completes
        // each list.
        unsafe {
            let next = sys::nbl_next(nbl);
            let (taken, payload) = split(&handles, module, nbl, true, &mut copies);
            if taken {
                // Absorbed, as if sent. An LSOv1 completion reports the TCP payload sent.
                let oob = Oob::of(nbl, true);
                if oob.mss() != 0 && !oob.lso_v2() {
                    sys::set_nbl_info(
                        nbl,
                        sys::TCP_LARGE_SEND_INFO,
                        (payload & 0x3fff_ffff) as usize,
                    );
                }
                sys::set_nbl_status(nbl, sys::NDIS_STATUS_SUCCESS);
                done.push(nbl);
            } else {
                pass.push(nbl);
            }
            nbl = next;
        }
    }
    // SAFETY: the lists are the filter's to pass or complete.
    unsafe {
        if admit(module, &mut copies) {
            pass.append(copies);
        }
        if !pass.head.is_null() {
            sys::NdisFSendNetBufferLists(module.handle, pass.head, port, flags);
        }
        if !done.head.is_null() {
            let complete = if flags & SEND_DISPATCH != 0 {
                SEND_COMPLETE_DISPATCH
            } else {
                0
            };
            sys::NdisFSendNetBufferListsComplete(module.handle, done.head, complete);
        }
    }
}

unsafe extern "C" fn send_complete(
    context: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    flags: u32,
) {
    let module = module(context);
    let mut theirs = Chain::new();
    let mut nbl = nbls;
    while !nbl.is_null() {
        // SAFETY: NDIS passes a valid chain of completed sends.
        unsafe {
            let next = sys::nbl_next(nbl);
            if is_own(nbl) {
                free_own(nbl);
                module.leave();
            } else {
                theirs.push(nbl);
            }
            nbl = next;
        }
    }
    if !theirs.head.is_null() {
        // SAFETY: completes the sends that came from above.
        unsafe { sys::NdisFSendNetBufferListsComplete(module.handle, theirs.head, flags) };
    }
}

unsafe extern "C" fn receive(
    context: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    port: sys::NDIS_PORT_NUMBER,
    count: u32,
    flags: u32,
) {
    let module = module(context);
    let Some(handles) = snapshot() else {
        // SAFETY: NDIS passes a valid chain, which goes on.
        unsafe { sys::NdisFIndicateReceiveNetBufferLists(module.handle, nbls, port, count, flags) };
        return;
    };
    let resources = flags & RECEIVE_RESOURCES != 0;
    let (mut pass, mut taken, mut copies) = (Chain::new(), Chain::new(), Chain::new());
    let mut any_taken = false;
    let mut nbl = nbls;
    while !nbl.is_null() {
        // SAFETY: NDIS passes a valid chain.
        unsafe {
            let next = sys::nbl_next(nbl);
            let mut mixed = Chain::new();
            let (took, _) = split(&handles, module, nbl, false, &mut mixed);
            if resources {
                // The miniport takes its lists back when this returns, so the chain cannot be
                // split: once a frame is taken, the ones that go on go as copies.
                if took && !any_taken {
                    let mut earlier = nbls;
                    while earlier != nbl {
                        copy_nb_list(module, earlier, &mut copies);
                        earlier = sys::nbl_next(earlier);
                    }
                } else if !took && any_taken {
                    copy_nb_list(module, nbl, &mut copies);
                }
            } else if took {
                taken.push(nbl);
            } else {
                pass.push(nbl);
            }
            copies.append(mixed);
            any_taken |= took;
            nbl = next;
        }
    }
    let dispatch = flags & RECEIVE_DISPATCH;
    // SAFETY: the lists are the filter's to indicate or return.
    unsafe {
        if resources && !any_taken {
            // Nothing taken: the chain goes up as it came.
            sys::NdisFIndicateReceiveNetBufferLists(module.handle, nbls, port, count, flags);
            return;
        }
        if !pass.head.is_null() {
            sys::NdisFIndicateReceiveNetBufferLists(
                module.handle,
                pass.head,
                port,
                pass.len,
                flags,
            );
        }
        if !taken.head.is_null() {
            let ret = if dispatch != 0 { RETURN_DISPATCH } else { 0 };
            sys::NdisFReturnNetBufferLists(module.handle, taken.head, ret);
        }
        let n = copies.len;
        if n > 0 && admit(module, &mut copies) {
            // The filter's own lists, without RESOURCES: they come back through `return_nbls`.
            sys::NdisFIndicateReceiveNetBufferLists(module.handle, copies.head, port, n, dispatch);
        }
    }
}

/// Copies of every frame of `nbl`, in the filter's own lists, pushed to `chain`.
///
/// # Safety
///
/// `nbl` is a valid NET_BUFFER_LIST.
unsafe fn copy_nb_list(module: &Module, nbl: *mut sys::NET_BUFFER_LIST, chain: &mut Chain) {
    // SAFETY: the caller's contract.
    let mut nb = unsafe { sys::nbl_first_nb(nbl) };
    while !nb.is_null() {
        // SAFETY: as above.
        unsafe {
            if let Some(c) = copy_nb(module, nbl, nb) {
                chain.push(c);
            }
            nb = sys::nb_next(nb);
        }
    }
}

unsafe extern "C" fn return_nbls(
    context: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    flags: u32,
) {
    let module = module(context);
    let mut theirs = Chain::new();
    let mut nbl = nbls;
    while !nbl.is_null() {
        // SAFETY: NDIS passes a valid chain of returned indications.
        unsafe {
            let next = sys::nbl_next(nbl);
            if is_own(nbl) {
                free_own(nbl);
                module.leave();
            } else {
                theirs.push(nbl);
            }
            nbl = next;
        }
    }
    if !theirs.head.is_null() {
        // SAFETY: returns the indications that came from below.
        unsafe { sys::NdisFReturnNetBufferLists(module.handle, theirs.head, flags) };
    }
}

/// Sends `frame` out of (outbound) or into (inbound) the adapter `addr.if_idx`, for a handle of
/// `priority`: what `SEND` does at the ETHERNET layer. Handles of lower priorities see the frame
/// first, as an impostor, and may take it.
///
/// A context the filter wrote for a frame captured on the same adapter restores what came out
/// of band: the outer 802.1Q tag goes back out of the frame, and a large send gets its request
/// and the partial TCP checksum the card completes. Other frames go as they are; the card drops
/// one larger than its MTU.
///
/// At PASSIVE_LEVEL.
pub fn send(frame: &[u8], addr: &Address, priority: i16) -> sys::NTSTATUS {
    if frame.len() < 14 {
        return sys::STATUS_INVALID_PARAMETER;
    }
    let Some(module) = MODULES
        .lock()
        .iter()
        .find(|m| m.if_idx == addr.if_idx)
        .cloned()
    else {
        return sys::STATUS_INVALID_PARAMETER;
    };
    let ctx = EthernetContext::decode(&addr.context).filter(|c| c.if_idx == addr.if_idx);
    let Some(mut data) = sys::try_copy(frame) else {
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    };
    let mut tag = 0;
    let mut lso = 0;
    if let Some(c) = ctx {
        if c.flags & EthernetContext::VLAN_OFFLOADED != 0
            && data.len() >= 18
            && data[12..14] == [0x81, 0x00]
        {
            let tci = u16::from_be_bytes([data[14], data[15]]) as usize;
            // NDIS_NET_BUFFER_LIST_8021Q_INFO, from the TCI.
            tag = (tci >> 13) | (((tci >> 12) & 1) << 3) | ((tci & 0xfff) << 4);
            data.drain(12..16);
        }
        if c.lso()
            && addr.outbound
            && let Some(off) = checksum::tcp_large_send(&mut data, Link::Ethernet)
        {
            let v6 = Packet::parse(&data, Link::Ethernet).ipv6().is_some();
            lso = if c.flags & EthernetContext::LSO_V2 != 0 {
                // LsoV2Transmit: MSS:20, TcpHeaderOffset:10, Type:2, IPVersion:2.
                (c.lso_mss as usize & 0xf_ffff)
                    | ((off & 0x3ff) << 20)
                    | (LSO_V2_TYPE << 30)
                    | (usize::from(v6) << 32)
            } else {
                (c.lso_mss as usize & 0xf_ffff) | ((off & 0x3ff) << 20)
            };
        }
    }
    if !module.enter(1) {
        return sys::STATUS_DEVICE_NOT_READY;
    }
    // A new copy, of the frame's final length: boxing `data` after a tag was taken out would
    // reallocate, which panics if it fails.
    let Some(nbl) = sys::try_box(&data).and_then(|data| alloc_own(&module, data)) else {
        module.leave();
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: a fresh list of ours.
    unsafe {
        sys::set_nbl_info(nbl, sys::IEEE_8021Q_INFO, tag);
        sys::set_nbl_info(nbl, sys::TCP_LARGE_SEND_INFO, lso);
    }
    if let Some(handles) = snapshot() {
        // SAFETY: a valid list of ours, with one NET_BUFFER.
        let (fate, _) = unsafe {
            let oob = Oob::of(nbl, addr.outbound);
            process(
                &handles,
                &module,
                sys::nbl_first_nb(nbl),
                &oob,
                addr.outbound,
                Some(priority),
            )
        };
        if fate == Fate::Taken {
            // SAFETY: never sent.
            unsafe { free_own(nbl) };
            module.leave();
            return sys::STATUS_SUCCESS;
        }
    }
    // SAFETY: a valid list of ours, which comes back through `send_complete` or `return_nbls`.
    unsafe {
        if addr.outbound {
            sys::NdisFSendNetBufferLists(module.handle, nbl, 0, 0);
        } else {
            sys::NdisFIndicateReceiveNetBufferLists(module.handle, nbl, 0, 1, 0);
        }
    }
    sys::STATUS_SUCCESS
}
