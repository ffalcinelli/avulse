//! Opening handles, and the calls on an open handle.

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use avulse_filter::{Filter, Layer};

use crate::backend::{self, Backend, Opened, Spec};
use crate::{Address, Error, Flags, MAX_PACKET_LEN, Param, Result, Shutdown};

/// The highest priority: the handle sees packets before every other handle.
pub const PRIORITY_HIGHEST: i16 = 30_000;
/// The lowest priority.
pub const PRIORITY_LOWEST: i16 = -30_000;

/// The language of a handle's filter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Syntax {
    /// Avulse's language, a subset of Wireshark's display filters
    /// ([`Filter::compile`]).
    #[default]
    Native,
    /// WinDivert 2.2's filter language ([`Filter::compile_windivert`]).
    WinDivert,
}

/// How to open a handle, beyond the filter and the layer.
///
/// ```no_run
/// use avulse::{Flags, Layer, OpenOptions};
///
/// let handle = OpenOptions::new()
///     .priority(100)
///     .flags(Flags::SNIFF)
///     .interfaces(["eth0"])
///     .open("arp or vlan", Layer::Ethernet)?;
/// # Ok::<(), avulse::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    priority: i16,
    flags: Flags,
    syntax: Syntax,
    interfaces: Vec<String>,
}

impl OpenOptions {
    /// Priority 0, no flags, the native syntax, every interface.
    pub fn new() -> Self {
        Self::default()
    }

    /// The priority, from [`PRIORITY_LOWEST`] to [`PRIORITY_HIGHEST`]. Handles with a higher
    /// priority see packets first. 0 places the handle after every handle open so far.
    pub fn priority(&mut self, priority: i16) -> &mut Self {
        self.priority = priority;
        self
    }

    /// The flags.
    pub fn flags(&mut self, flags: Flags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// The filter's language.
    pub fn syntax(&mut self, syntax: Syntax) -> &mut Self {
        self.syntax = syntax;
        self
    }

    /// Capture only on these interfaces (by name), instead of all of them. Loopback traffic is
    /// still seen where the backend needs the loopback interface for it.
    pub fn interfaces<I, S>(&mut self, names: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.interfaces = names.into_iter().map(Into::into).collect();
        self
    }

    /// Opens a handle at `layer` for the packets or events `filter` matches.
    pub fn open(&self, filter: &str, layer: Layer) -> Result<Handle> {
        self.open_with(backend::platform(), filter, layer)
    }

    pub(crate) fn open_with(
        &self,
        backend: &dyn Backend,
        filter: &str,
        layer: Layer,
    ) -> Result<Handle> {
        if !(PRIORITY_LOWEST..=PRIORITY_HIGHEST).contains(&self.priority) {
            return Err(Error::InvalidArgument(
                "the priority must be between -30000 and 30000",
            ));
        }
        check_flags(layer, self.flags)?;
        let filter = match self.syntax {
            Syntax::Native => Filter::compile(filter)?,
            Syntax::WinDivert => Filter::compile_windivert(filter, layer)?,
        };
        check_support(backend, layer, self.flags)?;
        let params = Param::ALL.map(Param::default_value);
        let opened = backend.open(&Spec {
            filter: &filter,
            layer,
            priority: self.priority,
            flags: self.flags,
            interfaces: &self.interfaces,
            params,
        })?;
        Ok(Handle {
            inner: Some(opened),
            filter,
            layer,
            priority: self.priority,
            flags: self.flags,
            params: params.map(AtomicU64::new),
        })
    }
}

/// The flag rules of WinDivert, which the backends rely on.
fn check_flags(layer: Layer, flags: Flags) -> Result<()> {
    if flags.contains(Flags::SNIFF | Flags::DROP) {
        return Err(Error::InvalidArgument("SNIFF and DROP exclude each other"));
    }
    if flags.contains(Flags::RECV_ONLY | Flags::SEND_ONLY) {
        return Err(Error::InvalidArgument(
            "RECV_ONLY and SEND_ONLY exclude each other",
        ));
    }
    match layer {
        Layer::Flow | Layer::Reflect if !flags.contains(Flags::SNIFF | Flags::RECV_ONLY) => Err(
            Error::InvalidArgument("the FLOW and REFLECT layers need SNIFF | RECV_ONLY"),
        ),
        Layer::Socket if !flags.contains(Flags::RECV_ONLY) => {
            Err(Error::InvalidArgument("the SOCKET layer needs RECV_ONLY"))
        }
        _ => Ok(()),
    }
}

/// Refuses what the backend says it cannot do, before it tries.
fn check_support(backend: &dyn Backend, layer: Layer, flags: Flags) -> Result<()> {
    let s = backend.capabilities().layer(layer);
    if !s.open {
        // The backend's own error says more (no backend, or not this layer).
        return Ok(());
    }
    if flags.contains(Flags::DROP) && !s.drop {
        return Err(Error::Unsupported("DROP at this layer"));
    }
    let receives = !flags.contains(Flags::SEND_ONLY);
    let diverts = receives && !flags.contains(Flags::SNIFF) && !flags.contains(Flags::DROP);
    if diverts && !s.divert {
        return Err(Error::Unsupported(
            "diverting at this layer (open it with SNIFF)",
        ));
    }
    Ok(())
}

/// An open handle: it receives the packets or events its filter matches, and sends packets.
///
/// `Handle` is `Send` and `Sync`: one thread can receive while another sends. Dropping it closes
/// it; [`close`](Handle::close) does the same and reports errors.
///
/// ```no_run
/// use avulse::{Flags, Handle, Layer, MAX_PACKET_LEN};
///
/// // Divert outbound HTTP, and send it on unchanged.
/// let handle = Handle::open("outbound and tcp.dstport == 80", Layer::Network, 0, Flags::NONE)?;
/// let mut buf = vec![0; MAX_PACKET_LEN];
/// loop {
///     let (len, addr) = handle.recv(&mut buf)?;
///     handle.send(&buf[..len], &addr)?;
/// }
/// # Ok::<(), avulse::Error>(())
/// ```
pub struct Handle {
    /// `Some` until `close` or `drop` takes it.
    inner: Option<Box<dyn Opened>>,
    filter: Filter,
    layer: Layer,
    priority: i16,
    flags: Flags,
    params: [AtomicU64; 3],
}

impl Handle {
    /// Opens a handle with a native filter. See [`OpenOptions`] for more options.
    pub fn open(filter: &str, layer: Layer, priority: i16, flags: Flags) -> Result<Handle> {
        OpenOptions::new()
            .priority(priority)
            .flags(flags)
            .open(filter, layer)
    }

    /// Opens a handle with a WinDivert filter, as `WinDivertOpen` does.
    pub fn open_windivert(
        filter: &str,
        layer: Layer,
        priority: i16,
        flags: Flags,
    ) -> Result<Handle> {
        OpenOptions::new()
            .priority(priority)
            .flags(flags)
            .syntax(Syntax::WinDivert)
            .open(filter, layer)
    }

    fn inner(&self) -> &dyn Opened {
        self.inner
            .as_deref()
            .expect("a handle is open until close or drop")
    }

    /// Waits for the next packet or event, copies it to `buf` and returns its length and
    /// address. [`MAX_PACKET_LEN`] bytes hold any packet; a packet that does not fit is dropped
    /// ([`Error::BufferTooSmall`]). After [`shutdown`](Handle::shutdown), it returns what is
    /// queued, then [`Error::Shutdown`].
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Address)> {
        self.check_recv()?;
        self.inner().recv(buf, None)
    }

    /// [`recv`](Handle::recv), waiting at most `timeout` ([`Error::Timeout`]). A zero timeout
    /// only takes a packet that is already queued.
    pub fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, Address)> {
        self.check_recv()?;
        self.inner().recv(buf, Some(timeout))
    }

    /// Receives several packets or events at once: it waits for the first as
    /// [`recv`](Handle::recv) does (at most `timeout`, or forever with `None`), then takes those
    /// already there, as long as `buf` and the slices have room. The packets are stored back to
    /// back in `buf`; packet `i` has length `lens[i]` and address `addrs[i]`. Returns how many
    /// there are, at least 1. A packet that does not fit what is left of `buf` waits for the
    /// next call; the first one, if it does not fit, is dropped ([`Error::BufferTooSmall`]).
    pub fn recv_batch(
        &self,
        buf: &mut [u8],
        addrs: &mut [Address],
        lens: &mut [usize],
        timeout: Option<Duration>,
    ) -> Result<usize> {
        self.check_recv()?;
        let max = addrs.len().min(lens.len());
        if max == 0 {
            return Err(Error::InvalidArgument(
                "recv_batch needs room for at least one address and length",
            ));
        }
        let (n, addr) = self.inner().recv(buf, timeout)?;
        (lens[0], addrs[0]) = (n, addr);
        let (mut used, mut count) = (n, 1);
        while count < max {
            // What was received is kept even when a later call fails.
            let Ok(Some((n, addr))) = self.inner().recv_ready(&mut buf[used..]) else {
                break;
            };
            (lens[count], addrs[count]) = (n, addr);
            used += n;
            count += 1;
        }
        Ok(count)
    }

    fn check_recv(&self) -> Result<()> {
        if self.flags.contains(Flags::SEND_ONLY) {
            return Err(Error::InvalidArgument(
                "the handle was opened with SEND_ONLY",
            ));
        }
        Ok(())
    }

    /// Sends (injects) a packet. `addr` is the address it was received with, possibly modified,
    /// or a new one ([`Address::new`]) for the handle's layer. The packet starts with the IP
    /// header, or with the Ethernet header at the ETHERNET layer.
    pub fn send(&self, packet: &[u8], addr: &Address) -> Result<usize> {
        if self.flags.contains(Flags::RECV_ONLY) {
            return Err(Error::InvalidArgument(
                "the handle was opened with RECV_ONLY",
            ));
        }
        if !matches!(
            self.layer,
            Layer::Network | Layer::NetworkForward | Layer::Ethernet
        ) {
            return Err(Error::InvalidArgument(
                "only the NETWORK, NETWORK_FORWARD and ETHERNET layers send packets",
            ));
        }
        if addr.layer != self.layer {
            return Err(Error::InvalidArgument(
                "the address is for another layer than the handle's",
            ));
        }
        if packet.is_empty() || packet.len() > MAX_PACKET_LEN {
            return Err(Error::InvalidArgument("the packet is empty or too long"));
        }
        self.inner().send(packet, addr)
    }

    /// Sends several packets, in order: packet `i` with address `addrs[i]` ([`send`](Handle::send)
    /// for each). Returns how many were sent; when a packet fails, the ones after it are not
    /// sent, and the error is returned only if it was the first.
    pub fn send_batch(&self, packets: &[&[u8]], addrs: &[Address]) -> Result<usize> {
        if packets.is_empty() || packets.len() != addrs.len() {
            return Err(Error::InvalidArgument(
                "send_batch needs as many addresses as packets, and at least one",
            ));
        }
        for (i, (packet, addr)) in packets.iter().zip(addrs).enumerate() {
            if let Err(e) = self.send(packet, addr) {
                return if i == 0 { Err(e) } else { Ok(i) };
            }
        }
        Ok(packets.len())
    }

    /// Stops receiving, sending, or both. It cannot be undone.
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        self.inner().shutdown(how)
    }

    /// Sets a queue parameter; `value` must be in [`Param::range`].
    pub fn set_param(&self, param: Param, value: u64) -> Result<()> {
        if !param.range().contains(&value) {
            return Err(Error::InvalidArgument("the parameter is out of range"));
        }
        self.inner().set_param(param, value)?;
        self.params[param.index()].store(value, Ordering::Relaxed);
        Ok(())
    }

    /// The value of a queue parameter.
    pub fn param(&self, param: Param) -> u64 {
        self.params[param.index()].load(Ordering::Relaxed)
    }

    /// The compiled filter, with its warnings ([`Filter::warnings`]).
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// The layer.
    pub fn layer(&self) -> Layer {
        self.layer
    }

    /// The priority it was opened with.
    pub fn priority(&self) -> i16 {
        self.priority
    }

    /// The flags.
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Closes the handle: packets stop being diverted, and those still queued are lost. It
    /// waits for calls in progress on other threads.
    pub fn close(mut self) -> Result<()> {
        match self.inner.take() {
            Some(inner) => inner.close(),
            None => Ok(()),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let _ = inner.close();
        }
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("layer", &self.layer)
            .field("priority", &self.priority)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// Readable when [`recv`](Handle::recv) would not block, for `poll`, `epoll` and async runtimes.
#[cfg(unix)]
impl AsFd for Handle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner().as_fd()
    }
}
