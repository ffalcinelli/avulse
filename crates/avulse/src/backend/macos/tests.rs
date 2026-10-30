//! What the macOS backend does without privileges: bpf records to packets and addresses, the
//! direction rule, the reinjection context, and how packets are sent.
//! `tests/capture_macos.rs` runs the rest, as root, on GitHub's macOS runners.

use std::net::{IpAddr, Ipv4Addr};

use avulse_filter::Layer;

use avulse_abi::macos::MacContext as Ctx;

use super::record::{self, Frame, Source};
use super::send::{self, Path};
use super::sys::{DLT_EN10MB, DLT_NULL};
use crate::{Address, Context, Error};

const HOST_MAC: [u8; 6] = [0x66, 0x65, 0x74, 0x68, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x99];

/// A UDP datagram from 10.77.1.2 to 10.77.1.1, port 47000 to 47001 (checksums not computed).
fn udp4() -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 30, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 10, 77, 1, 2, 10, 77, 1, 1, //
        0xb7, 0x98, 0xb7, 0x99, 0, 10, 0, 0, b'h', b'i',
    ];
    avulse_proto::checksum::recalculate(&mut p, avulse_proto::Link::Ip);
    p
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A bpf record: the 18-byte header (padded to `hdrlen`), the data, and the padding to 4 bytes.
fn record(sec: u32, usec: u32, hdrlen: u16, data: &[u8], datalen: usize) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&sec.to_ne_bytes());
    r.extend_from_slice(&usec.to_ne_bytes());
    r.extend_from_slice(&(data.len() as u32).to_ne_bytes());
    r.extend_from_slice(&(datalen as u32).to_ne_bytes());
    r.extend_from_slice(&hdrlen.to_ne_bytes());
    r.resize(hdrlen as usize, 0);
    r.extend_from_slice(data);
    r.resize(r.len().div_ceil(4) * 4, 0);
    r
}

fn feth1(outbound: Option<bool>) -> Source {
    Source {
        outbound,
        ifindex: 7,
        dlt: DLT_EN10MB,
        loopback: false,
        mac: Some(HOST_MAC),
        addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 77, 1, 1))],
    }
}

#[test]
fn records_are_split_and_aligned() {
    let a = eth(HOST_MAC, PEER_MAC, 0x0800, &udp4());
    let b = [2, 0, 0, 0, 0x45];
    let mut buf = record(10, 500, 18, &a, a.len());
    // lo0's records: bpf pads the header to 20 bytes so the IP header is aligned.
    buf.extend(record(11, 0, 20, &b, 100));
    let frames: Vec<Frame<'_>> = record::frames(&buf).collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].data, &a[..]);
    assert_eq!(frames[0].wall_ns, 10_000_500_000);
    assert!(!frames[0].truncated);
    assert_eq!(frames[1].data, &b[..]);
    assert!(frames[1].truncated);

    // A record that claims more than the buffer holds ends the walk.
    let mut bad = record(1, 0, 18, &a, a.len());
    bad[8..12].copy_from_slice(&1000u32.to_ne_bytes());
    assert_eq!(record::frames(&bad).count(), 0);
    assert_eq!(record::frames(&buf[..10]).count(), 0);
}

#[test]
fn ethernet_frames_to_entries() {
    let ip = udp4();
    let frame = eth(HOST_MAC, PEER_MAC, 0x0800, &ip);
    let f = Frame {
        wall_ns: 1000,
        truncated: false,
        data: &frame,
    };
    // NETWORK: the IP packet, with the Ethernet header in the context.
    let e = record::entry(&f, &feth1(Some(false)), Layer::Network, 5).unwrap();
    assert_eq!(e.data, ip);
    assert_eq!(e.addr.timestamp, 1005);
    assert!(!e.addr.outbound && !e.addr.loopback && e.addr.sniffed && !e.addr.ipv6);
    assert!(e.addr.ip_checksum && e.addr.udp_checksum);
    assert_eq!(e.addr.if_idx, 7);
    let ctx = Ctx::decode(&e.addr.context).unwrap();
    assert_eq!((ctx.ifindex, ctx.l2()), (7, &frame[..14]));

    // ETHERNET: the frame, and nothing to keep.
    let e = record::entry(&f, &feth1(Some(true)), Layer::Ethernet, 0).unwrap();
    assert_eq!(e.data, frame);
    assert!(e.addr.outbound);
    assert!(Ctx::decode(&e.addr.context).unwrap().l2().is_empty());

    // A VLAN tag stays in the frame, and in the context at NETWORK.
    let mut tagged = frame[..12].to_vec();
    tagged.extend_from_slice(&[0x81, 0, 0, 100]);
    tagged.extend_from_slice(&frame[12..]);
    let f = Frame { data: &tagged, ..f };
    let e = record::entry(&f, &feth1(Some(false)), Layer::Network, 0).unwrap();
    assert_eq!(e.data, ip);
    assert!(e.addr.vlan);
    assert_eq!(e.addr.vlan_tci, 100);
    assert_eq!(Ctx::decode(&e.addr.context).unwrap().l2(), &tagged[..18]);

    // No IP packet: nothing at NETWORK, the frame at ETHERNET.
    let arp = eth([0xff; 6], PEER_MAC, 0x0806, &[0; 28]);
    let f = Frame { data: &arp, ..f };
    assert!(record::entry(&f, &feth1(Some(false)), Layer::Network, 0).is_none());
    assert!(record::entry(&f, &feth1(Some(false)), Layer::Ethernet, 0).is_some());

    // A truncated capture is not delivered.
    let f = Frame {
        truncated: true,
        ..f
    };
    assert!(record::entry(&f, &feth1(Some(false)), Layer::Ethernet, 0).is_none());
}

#[test]
fn null_links_to_entries() {
    let ip = udp4();
    let mut data = 2u32.to_ne_bytes().to_vec();
    data.extend_from_slice(&ip);
    let f = Frame {
        wall_ns: 0,
        truncated: false,
        data: &data,
    };
    let lo = Source {
        outbound: None,
        ifindex: 1,
        dlt: DLT_NULL,
        loopback: true,
        mac: None,
        addrs: Vec::new(),
    };
    let e = record::entry(&f, &lo, Layer::Network, 0).unwrap();
    assert_eq!(e.data, ip);
    assert!(e.addr.loopback && e.addr.outbound);
    assert!(Ctx::decode(&e.addr.context).unwrap().l2().is_empty());
    // No frames on lo0 or utun.
    assert!(record::entry(&f, &lo, Layer::Ethernet, 0).is_none());

    // utun, without a direction: outbound when the source is one of its addresses.
    let utun = Source {
        loopback: false,
        addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 77, 1, 2))],
        ..lo
    };
    assert!(
        record::entry(&f, &utun, Layer::Network, 0)
            .unwrap()
            .addr
            .outbound
    );
    let utun = Source {
        addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 77, 1, 1))],
        ..utun
    };
    assert!(
        !record::entry(&f, &utun, Layer::Network, 0)
            .unwrap()
            .addr
            .outbound
    );
}

#[test]
fn direction_without_the_ioctl() {
    // On Ethernet, a frame from the interface's own MAC address is outbound.
    let ip = udp4();
    let out = eth(PEER_MAC, HOST_MAC, 0x0800, &ip);
    let inb = eth(HOST_MAC, PEER_MAC, 0x0800, &ip);
    let src = feth1(None);
    for (frame, outbound) in [(&out, true), (&inb, false)] {
        let f = Frame {
            wall_ns: 0,
            truncated: false,
            data: frame,
        };
        let e = record::entry(&f, &src, Layer::Ethernet, 0).unwrap();
        assert_eq!(e.addr.outbound, outbound);
        // The device's direction wins when there is one.
        let e = record::entry(&f, &feth1(Some(!outbound)), Layer::Ethernet, 0).unwrap();
        assert_eq!(e.addr.outbound, !outbound);
    }
}

#[test]
fn contexts() {
    let mut b = [0u8; 64];
    b[0] = 0xa1; // Linux's
    assert_eq!(Ctx::decode(&Context::from_bytes(b)), None);
}

#[test]
fn send_paths() {
    let ip = udp4();
    let mut addr = Address::new(Layer::Network);
    // IPv4 goes through the raw socket, either way.
    assert_eq!(
        send::path(Layer::Network, &addr, &ip).ok(),
        Some(Path::Raw { at: 0 })
    );
    addr.outbound = true;
    assert_eq!(
        send::path(Layer::Network, &addr, &ip).ok(),
        Some(Path::Raw { at: 0 })
    );

    // IPv6 goes in through the utun, and out behind the Ethernet header it was captured with.
    let mut ip6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
    ip6.extend_from_slice(&[0; 32]);
    ip6.extend_from_slice(&[0; 8]);
    addr.outbound = false;
    assert_eq!(
        send::path(Layer::Network, &addr, &ip6).ok(),
        Some(Path::Utun { at: 0 })
    );
    addr.outbound = true;
    assert!(matches!(
        send::path(Layer::Network, &addr, &ip6),
        Err(Error::Unsupported(_))
    ));
    let frame = eth(PEER_MAC, HOST_MAC, 0x0800, &ip);
    let f = Frame {
        wall_ns: 0,
        truncated: false,
        data: &frame,
    };
    let captured = record::entry(&f, &feth1(Some(true)), Layer::Network, 0).unwrap();
    addr.if_idx = 7;
    addr.context = captured.addr.context;
    let mut l2 = frame[..14].to_vec();
    l2[12..].copy_from_slice(&[0x86, 0xdd]);
    assert_eq!(
        send::path(Layer::Network, &addr, &ip6).ok(),
        Some(Path::Bpf { ifindex: 7, l2 })
    );
    addr.loopback = true;
    assert!(send::path(Layer::Network, &addr, &ip6).is_err());

    // ETHERNET: out through bpf; in only for IP, as at NETWORK.
    let mut addr = Address::new(Layer::Ethernet);
    assert!(matches!(
        send::path(Layer::Ethernet, &addr, &frame),
        Err(Error::InvalidArgument(_))
    ));
    addr.if_idx = 7;
    assert_eq!(
        send::path(Layer::Ethernet, &addr, &frame).ok(),
        Some(Path::Raw { at: 14 })
    );
    let arp = eth([0xff; 6], PEER_MAC, 0x0806, &[0; 28]);
    assert!(matches!(
        send::path(Layer::Ethernet, &addr, &arp),
        Err(Error::Unsupported(_))
    ));
    addr.outbound = true;
    assert_eq!(
        send::path(Layer::Ethernet, &addr, &arp).ok(),
        Some(Path::Bpf {
            ifindex: 7,
            l2: Vec::new()
        })
    );
}

/// The extension tier against the extension's XPC service in its test mode (`drivers/macos/
/// scripts/test.sh` runs it as a daemon, then these, as root, with `AVULSE_EXTENSION_TEST` and
/// `AVULSE_MACH_SERVICE` set). Packets come through `TestPacket`, as the provider would hand
/// them over.
mod extension_tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    use avulse_abi::macos::{Op, Request, Status, TestPacket, encode_test_packet};
    use avulse_filter::Layer;

    use super::super::xpc::Connection;
    use crate::{Error, Flags, Handle, MAX_PACKET_LEN, Shutdown, capabilities};

    fn enabled() -> bool {
        if std::env::var_os("AVULSE_EXTENSION_TEST").is_some() {
            return true;
        }
        eprintln!("skipped: run by drivers/macos/scripts/test.sh, against the extension's daemon");
        false
    }

    /// A UDP datagram from 127.0.0.1:47000 to 127.0.0.1:`port`, checksums right.
    fn udp(port: u16, payload: &[u8]) -> Vec<u8> {
        let len = 28 + payload.len();
        let mut p = vec![
            0x45, 0, 0, 0, 0x12, 0x34, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1, //
            0xb7, 0x98, 0, 0, 0, 0, 0, 0,
        ];
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(payload);
        avulse_proto::checksum::recalculate(&mut p, avulse_proto::Link::Ip);
        p
    }

    /// Hands `data` to the extension's packet path; returns the verdict (0 allow, 1 drop, 2
    /// delay).
    fn test_packet(conn: &Connection, data: &[u8]) -> u32 {
        let payload = encode_test_packet(&TestPacket {
            ifindex: 1,
            outbound: true,
            loopback: true,
            data,
        });
        let (s, p) = conn
            .call(&Request {
                op: Op::TestPacket,
                handle: 0,
                payload: &payload,
            })
            .unwrap();
        assert_eq!(s, Status::Ok);
        u32::from_le_bytes(p[..4].try_into().unwrap())
    }

    fn recv(h: &Handle) -> (Vec<u8>, crate::Address) {
        let mut buf = vec![0; MAX_PACKET_LEN];
        let (n, addr) = h.recv_timeout(&mut buf, Duration::from_secs(2)).unwrap();
        (buf[..n].to_vec(), addr)
    }

    #[test]
    fn extension_capabilities() {
        if !enabled() {
            return;
        }
        let c = capabilities().layer(Layer::Network);
        assert!(
            c.open && c.divert && c.drop && c.inject && c.modify,
            "{c:?}"
        );
        // Opening a diverting handle no longer needs SNIFF.
        Handle::open("udp", Layer::Network, 0, Flags::NONE).unwrap();
    }

    #[test]
    fn extension_divert_and_send_back() {
        if !enabled() {
            return;
        }
        let conn = Connection::open().unwrap();
        let h = Handle::open("udp.dstport == 47500", Layer::Network, 0, Flags::NONE).unwrap();
        assert_eq!(test_packet(&conn, &udp(1, b"")), 0);
        let pkt = udp(47500, b"held");
        assert_eq!(test_packet(&conn, &pkt), 2);
        let (data, addr) = recv(&h);
        assert_eq!(data, pkt);
        assert!(!addr.sniffed && addr.loopback && addr.outbound);
        // Unchanged: the extension lets the original go; nothing is injected.
        h.send(&data, &addr).unwrap();
        let s = h.stats().unwrap();
        assert_eq!(s.diverted, 1);
    }

    #[test]
    fn extension_modified_packets_are_injected() {
        if !enabled() {
            return;
        }
        let conn = Connection::open().unwrap();
        let rx = UdpSocket::bind("127.0.0.1:47501").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let h = Handle::open("udp.dstport == 47501", Layer::Network, 0, Flags::NONE).unwrap();
        assert_eq!(test_packet(&conn, &udp(47501, b"old")), 2);
        let (_, addr) = recv(&h);
        // Modified: the client sends it, through the raw socket, to the bound socket.
        h.send(&udp(47501, b"new!"), &addr).unwrap();
        let mut b = [0; 16];
        assert_eq!(rx.recv(&mut b).unwrap(), 4);
        assert_eq!(&b[..4], b"new!");
    }

    #[test]
    fn extension_sniff_drop_and_priorities() {
        if !enabled() {
            return;
        }
        let conn = Connection::open().unwrap();
        let sniffer =
            Handle::open("udp.dstport == 47502", Layer::Network, 10, Flags::SNIFF).unwrap();
        let dropper = Handle::open("udp.dstport == 47502", Layer::Network, 0, Flags::DROP).unwrap();
        assert_eq!(test_packet(&conn, &udp(47502, b"")), 1);
        let (_, addr) = recv(&sniffer);
        assert!(addr.sniffed);
        assert_eq!(dropper.stats().unwrap().dropped, 1);
    }

    #[test]
    fn extension_shutdown_and_close() {
        if !enabled() {
            return;
        }
        let conn = Connection::open().unwrap();
        let h = Handle::open("udp.dstport == 47503", Layer::Network, 0, Flags::NONE).unwrap();
        std::thread::scope(|s| {
            let t = s.spawn(|| {
                let mut buf = vec![0; MAX_PACKET_LEN];
                h.recv(&mut buf).map(|(n, _)| n)
            });
            std::thread::sleep(Duration::from_millis(300));
            h.shutdown(Shutdown::Recv).unwrap();
            assert!(matches!(t.join().unwrap(), Err(Error::Shutdown)));
        });
        // Closed, the handle diverts nothing.
        h.close().unwrap();
        assert_eq!(test_packet(&conn, &udp(47503, b"")), 0);
    }

    /// Hands a flow's start or end to the extension's flow path; returns the verdict, the flow's
    /// id and whether its end is wanted.
    fn test_flow(conn: &Connection, f: &avulse_abi::macos::TestFlow) -> (u32, u64, bool) {
        let (s, p) = conn
            .call(&Request {
                op: Op::TestFlow,
                handle: 0,
                payload: &f.encode(),
            })
            .unwrap();
        assert_eq!(s, Status::Ok);
        (
            u32::from_le_bytes(p[..4].try_into().unwrap()),
            u64::from_le_bytes(p[8..16].try_into().unwrap()),
            p[16] == 1,
        )
    }

    #[test]
    fn extension_flows_sockets_and_reflect() {
        if !enabled() {
            return;
        }
        let conn = Connection::open().unwrap();
        let reflect =
            Handle::open("true", Layer::Reflect, 0, Flags::SNIFF | Flags::RECV_ONLY).unwrap();
        let refuser =
            Handle::open("remote.port == 47443", Layer::Socket, 0, Flags::RECV_ONLY).unwrap();
        let flows = Handle::open(
            "remote.port in {47443, 47080}",
            Layer::Flow,
            0,
            Flags::SNIFF | Flags::RECV_ONLY,
        )
        .unwrap();
        let mut f = avulse_abi::macos::TestFlow {
            outbound: true,
            protocol: 6,
            pid: 4242,
            remote_port: 47443,
            ..Default::default()
        };
        // Refused: the SOCKET handle gets the connect, the FLOW handle nothing.
        assert_eq!(test_flow(&conn, &f).0, 1);
        let (_, addr) = recv(&refuser);
        assert_eq!(addr.event, crate::Event::SocketConnect);
        assert_eq!((addr.flow.process_id, addr.flow.remote_port), (4242, 47443));
        // Allowed: established, then deleted.
        f.remote_port = 47080;
        let (v, id, watch) = test_flow(&conn, &f);
        assert_eq!((v, watch), (0, true));
        let (_, addr) = recv(&flows);
        assert_eq!(addr.event, crate::Event::FlowEstablished);
        f.end = true;
        f.id = id;
        test_flow(&conn, &f);
        let (_, addr) = recv(&flows);
        assert_eq!(addr.event, crate::Event::FlowDeleted);
        assert_eq!(addr.flow.endpoint_id, id);
        // REFLECT saw this process open the others.
        let mut opened = Vec::new();
        let mut buf = vec![0; MAX_PACKET_LEN];
        while let Ok((n, addr)) = reflect.recv_timeout(&mut buf, Duration::from_millis(300)) {
            if addr.reflect.process_id == std::process::id() {
                opened.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
        assert!(
            opened.contains(&"remote.port == 47443".to_string()),
            "{opened:?}"
        );
    }

    #[test]
    fn extension_a_client_that_goes_away_loses_its_handles() {
        if !enabled() {
            return;
        }
        let probe = Connection::open().unwrap();
        {
            let gone = Connection::open().unwrap();
            let req = avulse_abi::ioctl::OpenRequest {
                layer: Layer::Network,
                priority: 0,
                flags: Flags::NONE,
                program: &[],
                interfaces: Vec::new(),
                filter: "udp.dstport == 47504",
                syntax: crate::Syntax::Native,
                windivert_object: &[],
            };
            let (s, _) = gone
                .call(&Request {
                    op: Op::Open,
                    handle: 0,
                    payload: &req.encode(),
                })
                .unwrap();
            assert_eq!(s, Status::Ok);
            assert_eq!(test_packet(&probe, &udp(47504, b"")), 2);
        }
        // The connection is cancelled: its handle closes, and the packet path lets packets by.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(test_packet(&probe, &udp(47504, b"")), 0);
    }
}
