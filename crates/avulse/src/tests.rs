//! Tests of the API on a fake backend: argument checks, what reaches the backend, the address
//! layout.

use std::mem::{align_of, offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::backend::{Backend, Capabilities, LayerSupport, Opened, Spec};
use crate::*;

/// What `Backend::open` got, with the filter in native syntax.
struct OpenedWith {
    filter: String,
    layer: Layer,
    priority: i16,
    flags: Flags,
    interfaces: Vec<String>,
    params: [u64; 3],
}

/// What the fake backend saw.
#[derive(Default)]
struct Log {
    opened: Vec<OpenedWith>,
    sent: Vec<(Vec<u8>, Address)>,
    params: Vec<(Param, u64)>,
    shutdowns: Vec<Shutdown>,
    closed: usize,
}

struct Fake {
    caps: Capabilities,
    log: Arc<Mutex<Log>>,
}

impl Fake {
    fn new() -> Self {
        let mut caps = Capabilities::NONE;
        for layer in [
            Layer::Network,
            Layer::NetworkForward,
            Layer::Flow,
            Layer::Socket,
            Layer::Reflect,
            Layer::Ethernet,
        ] {
            caps = caps.with(layer, LayerSupport::ALL);
        }
        Fake {
            caps,
            log: Arc::default(),
        }
    }

    fn open(&self, filter: &str, layer: Layer, flags: Flags) -> Result<Handle> {
        OpenOptions::new()
            .flags(flags)
            .open_with(self, filter, layer)
    }

    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.log.lock().unwrap()
    }
}

impl Backend for Fake {
    fn capabilities(&self) -> Capabilities {
        self.caps
    }

    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>> {
        self.log.lock().unwrap().opened.push(OpenedWith {
            filter: spec.filter.ir().native().to_string(),
            layer: spec.layer,
            priority: spec.priority,
            flags: spec.flags,
            interfaces: spec.interfaces.to_vec(),
            params: spec.params,
        });
        Ok(Box::new(FakeHandle {
            log: self.log.clone(),
            #[cfg(unix)]
            fd: std::fs::File::open("/dev/null").unwrap(),
        }))
    }
}

struct FakeHandle {
    log: Arc<Mutex<Log>>,
    #[cfg(unix)]
    fd: std::fs::File,
}

impl Opened for FakeHandle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        if timeout == Some(Duration::ZERO) {
            return Err(Error::Timeout);
        }
        let packet = [0x45u8, 0, 0, 20];
        let Some(dst) = buf.get_mut(..packet.len()) else {
            return Err(Error::BufferTooSmall {
                needed: packet.len(),
            });
        };
        dst.copy_from_slice(&packet);
        let mut addr = Address::new(Layer::Network);
        addr.outbound = true;
        Ok((packet.len(), addr))
    }

    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize> {
        self.log.lock().unwrap().sent.push((packet.to_vec(), *addr));
        Ok(packet.len())
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        self.log.lock().unwrap().shutdowns.push(how);
        Ok(())
    }

    fn set_param(&self, param: Param, value: u64) -> Result<()> {
        self.log.lock().unwrap().params.push((param, value));
        Ok(())
    }

    #[cfg(unix)]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    fn close(self: Box<Self>) -> Result<()> {
        self.log.lock().unwrap().closed += 1;
        Ok(())
    }
}

fn invalid(r: Result<Handle>) -> &'static str {
    match r {
        Err(Error::InvalidArgument(what)) => what,
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

#[test]
fn address_layout() {
    assert_eq!(size_of::<Address>(), 184);
    assert_eq!(align_of::<Address>(), 8);
    assert_eq!(offset_of!(Address, timestamp), 0);
    assert_eq!(offset_of!(Address, version), 8);
    assert_eq!(offset_of!(Address, layer), 10);
    assert_eq!(offset_of!(Address, event), 11);
    assert_eq!(offset_of!(Address, outbound), 12);
    assert_eq!(offset_of!(Address, udp_checksum), 19);
    assert_eq!(offset_of!(Address, if_idx), 20);
    assert_eq!(offset_of!(Address, sub_if_idx), 24);
    assert_eq!(offset_of!(Address, vlan_tci), 28);
    assert_eq!(offset_of!(Address, vlan), 30);
    assert_eq!(offset_of!(Address, flow), 32);
    assert_eq!(offset_of!(Address, reflect), 96);
    assert_eq!(offset_of!(Address, context), 120);
    assert_eq!(size_of::<Flow>(), 64);
    assert_eq!(offset_of!(Flow, local_addr), 24);
    assert_eq!(offset_of!(Flow, protocol), 56);
    assert_eq!(size_of::<Reflect>(), 24);
    assert_eq!(size_of::<Context>(), CONTEXT_LEN);
    assert_eq!(size_of::<Flags>(), 8);
}

#[test]
fn new_addresses() {
    let a = Address::new(Layer::Ethernet);
    assert_eq!(a.version(), ADDRESS_VERSION);
    assert_eq!(a.layer, Layer::Ethernet);
    assert_eq!(a.event, Event::Packet);
    assert!(!a.outbound && !a.ip_checksum && a.context.is_empty());
    assert_eq!(Address::default(), Address::new(Layer::Network));
    assert_eq!(format!("{:?}", a.context), "Context(empty)");
    let mut bytes = [0; CONTEXT_LEN];
    bytes[0] = 0xab;
    let c = Context::from_bytes(bytes);
    assert!(!c.is_empty());
    assert_eq!(c.as_bytes()[0], 0xab);
    assert!(format!("{c:?}").starts_with("Context(ab00"));
}

#[test]
fn flow_addresses() {
    let mut f = Flow::default();
    f.set_local_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    f.set_remote_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(
        f.local_addr,
        Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets()
    );
    assert_eq!(f.local_addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(f.remote_addr(), IpAddr::V6(Ipv6Addr::LOCALHOST));
}

#[test]
fn meta_of_an_address() {
    let mut a = Address::new(Layer::Socket);
    a.event = Event::SocketConnect;
    a.outbound = true;
    a.flow.process_id = 42;
    a.flow.remote_port = 443;
    a.flow.protocol = 6;
    a.flow
        .set_remote_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    let m = a.meta();
    assert_eq!(m.layer, Layer::Socket);
    assert_eq!(m.event, Event::SocketConnect);
    assert_eq!(m.process_id, Some(42));
    let flow = m.flow.unwrap();
    assert_eq!(flow.remote_port, 443);
    assert_eq!(flow.remote_addr, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

    let filter =
        Filter::compile("event == connect and process.pid == 42 and remote.port == 443").unwrap();
    let packet = proto::Packet::parse(&[], proto::Link::Ip);
    assert!(filter.matches(&packet, &m));

    let mut r = Address::new(Layer::Reflect);
    r.reflect.process_id = 7;
    r.reflect.priority = -5;
    assert_eq!(r.meta().process_id, Some(7));
    assert_eq!(r.meta().priority, -5);
    assert_eq!(Address::new(Layer::Network).meta().flow, None);
}

#[test]
fn flags() {
    assert_eq!(
        Flags::from_bits(0x21),
        Some(Flags::SNIFF | Flags::FRAGMENTS)
    );
    assert_eq!(Flags::from_bits(0x40), None);
    assert_eq!((Flags::SNIFF | Flags::RECV_ONLY).bits(), 5);
    assert!(Flags::NONE.is_empty());
    assert_eq!(format!("{:?}", Flags::NONE), "NONE");
    assert_eq!(
        format!("{:?}", Flags::DROP | Flags::NO_INSTALL),
        "DROP | NO_INSTALL"
    );
    let mut f = Flags::SNIFF;
    f |= Flags::RECV_ONLY;
    assert!(f.contains(Flags::RECV_ONLY) && !f.contains(Flags::DROP));
}

#[test]
fn params() {
    for p in Param::ALL {
        assert!(p.range().contains(&p.default_value()));
    }
    assert_eq!(Param::QueueTime.range(), 100..=16_000);
}

#[test]
fn open_checks_arguments() {
    let fake = Fake::new();
    let opts = |p: i16| {
        let mut o = OpenOptions::new();
        o.priority(p);
        o
    };
    assert!(invalid(opts(30_001).open_with(&fake, "tcp", Layer::Network)).contains("priority"));
    assert!(invalid(opts(-30_001).open_with(&fake, "tcp", Layer::Network)).contains("priority"));
    assert!(opts(30_000).open_with(&fake, "tcp", Layer::Network).is_ok());
    assert!(
        opts(-30_000)
            .open_with(&fake, "tcp", Layer::Network)
            .is_ok()
    );

    let net = |flags| fake.open("tcp", Layer::Network, flags);
    assert!(invalid(net(Flags::SNIFF | Flags::DROP)).contains("SNIFF and DROP"));
    assert!(invalid(net(Flags::RECV_ONLY | Flags::SEND_ONLY)).contains("RECV_ONLY"));
    assert!(net(Flags::SNIFF | Flags::FRAGMENTS | Flags::NO_INSTALL).is_ok());

    for layer in [Layer::Flow, Layer::Reflect] {
        assert!(invalid(fake.open("true", layer, Flags::SNIFF)).contains("SNIFF | RECV_ONLY"));
        assert!(
            fake.open("true", layer, Flags::SNIFF | Flags::RECV_ONLY)
                .is_ok()
        );
    }
    assert!(invalid(fake.open("true", Layer::Socket, Flags::NONE)).contains("RECV_ONLY"));
    assert!(fake.open("true", Layer::Socket, Flags::RECV_ONLY).is_ok());
}

#[test]
fn open_compiles_the_filter() {
    let fake = Fake::new();
    match fake.open("tcp.prot == 80", Layer::Network, Flags::NONE) {
        Err(Error::Filter(d)) => assert!(d.render("tcp.prot == 80").contains("tcp.port")),
        other => panic!("expected a filter error, got {other:?}"),
    }
    // WinDivert syntax only with `Syntax::WinDivert`.
    assert!(matches!(
        fake.open("tcp.DstPort == 80", Layer::Network, Flags::NONE),
        Err(Error::Filter(_))
    ));
    let h = OpenOptions::new()
        .syntax(Syntax::WinDivert)
        .open_with(&fake, "tcp.DstPort == 80", Layer::Network)
        .unwrap();
    assert_eq!(h.filter().ir().native().to_string(), "tcp.dstport == 80");
}

#[test]
fn open_respects_capabilities() {
    let mut fake = Fake::new();
    let sniff_only = LayerSupport {
        drop: false,
        divert: false,
        ..LayerSupport::ALL
    };
    fake.caps = fake.caps.with(Layer::Network, sniff_only);
    let unsupported = |r: Result<Handle>| matches!(r, Err(Error::Unsupported(_)));
    assert!(unsupported(fake.open("tcp", Layer::Network, Flags::NONE)));
    assert!(unsupported(fake.open("tcp", Layer::Network, Flags::DROP)));
    assert!(fake.open("tcp", Layer::Network, Flags::SNIFF).is_ok());
    assert!(fake.open("tcp", Layer::Network, Flags::SEND_ONLY).is_ok());
}

#[test]
fn open_passes_the_handle_to_the_backend() {
    let fake = Fake::new();
    let h = OpenOptions::new()
        .priority(-7)
        .flags(Flags::SNIFF)
        .interfaces(["eth0", "eth1"])
        .open_with(&fake, "tcp.port in {80 443}", Layer::Ethernet)
        .unwrap();
    assert_eq!(
        (h.layer(), h.priority(), h.flags()),
        (Layer::Ethernet, -7, Flags::SNIFF)
    );
    let log = fake.log();
    let o = &log.opened[0];
    assert_eq!(o.filter, "tcp.port in {80 443}");
    assert_eq!(
        (o.layer, o.priority, o.flags),
        (Layer::Ethernet, -7, Flags::SNIFF)
    );
    assert_eq!(o.interfaces, ["eth0", "eth1"]);
    assert_eq!(o.params, [4_096, 2_000, 4_194_304]);
}

#[test]
fn recv_and_send() {
    let fake = Fake::new();
    let h = fake.open("ip", Layer::Network, Flags::NONE).unwrap();
    let mut buf = [0; 64];
    let (len, addr) = h.recv(&mut buf).unwrap();
    assert_eq!(&buf[..len], [0x45, 0, 0, 20]);
    assert!(addr.outbound);
    assert!(matches!(
        h.recv(&mut [0; 2]),
        Err(Error::BufferTooSmall { needed: 4 })
    ));
    assert!(matches!(
        h.recv_timeout(&mut buf, Duration::ZERO),
        Err(Error::Timeout)
    ));
    assert_eq!(h.send(&buf[..len], &addr).unwrap(), 4);
    assert_eq!(fake.log().sent[0].0, [0x45, 0, 0, 20]);

    let err = |r: Result<usize>| match r {
        Err(Error::InvalidArgument(what)) => what,
        other => panic!("expected InvalidArgument, got {other:?}"),
    };
    assert!(err(h.send(&[], &addr)).contains("empty"));
    assert!(err(h.send(&vec![0; MAX_PACKET_LEN + 1], &addr)).contains("too long"));
    assert!(err(h.send(&buf[..len], &Address::new(Layer::Ethernet))).contains("another layer"));
    assert_eq!(fake.log().sent.len(), 1);
}

#[test]
fn directional_flags() {
    let fake = Fake::new();
    let recv_only = fake.open("ip", Layer::Network, Flags::RECV_ONLY).unwrap();
    assert!(matches!(
        recv_only.send(&[0x45], &Address::default()),
        Err(Error::InvalidArgument(w)) if w.contains("RECV_ONLY")
    ));
    let send_only = fake.open("ip", Layer::Network, Flags::SEND_ONLY).unwrap();
    assert!(matches!(
        send_only.recv(&mut [0; 64]),
        Err(Error::InvalidArgument(w)) if w.contains("SEND_ONLY")
    ));
    let flow = fake
        .open("true", Layer::Flow, Flags::SNIFF | Flags::RECV_ONLY)
        .unwrap();
    assert!(matches!(
        flow.send(&[0x45], &Address::new(Layer::Flow)),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn params_are_checked_and_kept() {
    let fake = Fake::new();
    let h = fake.open("ip", Layer::Network, Flags::NONE).unwrap();
    assert_eq!(h.param(Param::QueueLength), 4_096);
    assert!(matches!(
        h.set_param(Param::QueueLength, 31),
        Err(Error::InvalidArgument(_))
    ));
    h.set_param(Param::QueueLength, 32).unwrap();
    h.set_param(Param::QueueTime, 16_000).unwrap();
    assert_eq!(h.param(Param::QueueLength), 32);
    assert_eq!(h.param(Param::QueueTime), 16_000);
    assert_eq!(
        fake.log().params,
        [(Param::QueueLength, 32), (Param::QueueTime, 16_000)]
    );
}

#[test]
fn shutdown_and_close() {
    let fake = Fake::new();
    let h = fake.open("ip", Layer::Network, Flags::NONE).unwrap();
    h.shutdown(Shutdown::Recv).unwrap();
    assert_eq!(fake.log().shutdowns, [Shutdown::Recv]);
    h.close().unwrap();
    assert_eq!(fake.log().closed, 1);
    drop(fake.open("ip", Layer::Network, Flags::NONE).unwrap());
    assert_eq!(fake.log().closed, 2);
}

#[cfg(unix)]
#[test]
fn the_handle_is_pollable() {
    use std::os::fd::AsRawFd;
    let fake = Fake::new();
    let h = fake.open("ip", Layer::Network, Flags::NONE).unwrap();
    assert!(h.as_fd().as_raw_fd() >= 0);
}

#[test]
fn handles_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Handle>();
}

#[test]
fn no_backend_yet() {
    for layer in [Layer::Network, Layer::Ethernet, Layer::Flow] {
        assert_eq!(capabilities().layer(layer), LayerSupport::default());
    }
    assert!(matches!(
        Handle::open("tcp", Layer::Network, 0, Flags::NONE),
        Err(Error::Unsupported(_))
    ));
    // Arguments are still checked first.
    assert!(matches!(
        Handle::open("tcp", Layer::Network, 0, Flags::SNIFF | Flags::DROP),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn errors_display() {
    assert_eq!(Error::Timeout.to_string(), "timed out");
    assert_eq!(
        Error::BufferTooSmall { needed: 9 }.to_string(),
        "the packet (9 bytes) does not fit the buffer"
    );
    let e = Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert!(std::error::Error::source(&e).is_some());
}
