//! The REFLECT layer: the driver's own handles. Every open handle is in [`HANDLES`], oldest
//! first. A REFLECT handle that opens hears of each of them (OPEN, itself included), then of each
//! handle that opens or closes (CLOSE, also when its process exits). The data of an event is the
//! handle's filter as written, in its syntax.

use alloc::sync::Arc;
use alloc::vec::Vec;

use avulse_abi::Address;
use avulse_filter::{Event, Layer, Meta};
use avulse_proto::Link;

use crate::handle::Open;
use crate::lock::SpinLock;
use crate::{eval, wfp};

/// The open handles, in the order they opened.
static HANDLES: SpinLock<Vec<Arc<Open>>> = SpinLock::new(Vec::new());

/// Tells the REFLECT handle `to` about the handle `about`, if its filter matches.
fn report(to: &Open, about: &Open, event: Event) {
    if to.idle() {
        return;
    }
    let mut addr = Address::new(Layer::Reflect);
    addr.timestamp = wfp::now_ns();
    addr.event = event;
    addr.sniffed = true;
    let r = &mut addr.reflect;
    r.timestamp = about.opened;
    r.flags = about.flags;
    r.process_id = about.process_id;
    r.priority = about.priority;
    r.layer = about.layer;
    r.syntax = about.syntax;
    // At REFLECT, the metadata is the reflected handle's (its layer, priority and process).
    let m: Meta<'_> = addr.meta();
    if eval::evaluate(to.program(), &[], Link::Ip, &m) == Some(true) {
        to.deliver(addr, about.filter.as_bytes().to_vec());
    }
}

/// A handle opened: reported to every REFLECT handle; a REFLECT handle also hears of every
/// handle already open. The events go out under the lock, so that their order is the handles'.
pub fn opened(open: &Arc<Open>) {
    let mut handles = HANDLES.lock();
    handles.push(open.clone());
    if open.layer == Layer::Reflect {
        for h in handles.iter() {
            report(open, h, Event::ReflectOpen);
        }
    }
    for r in handles.iter() {
        if r.layer == Layer::Reflect && !Arc::ptr_eq(r, open) {
            report(r, open, Event::ReflectOpen);
        }
    }
}

/// A handle closed: reported to the REFLECT handles left.
pub fn closed(open: &Arc<Open>) {
    let mut handles = HANDLES.lock();
    let Some(i) = handles.iter().position(|h| Arc::ptr_eq(h, open)) else {
        return;
    };
    handles.remove(i);
    for r in handles.iter() {
        if r.layer == Layer::Reflect {
            report(r, open, Event::ReflectClose);
        }
    }
}

/// Frees the table's allocation, at unload (no handle is open).
pub fn free() {
    drop(core::mem::take(&mut *HANDLES.lock()));
}
