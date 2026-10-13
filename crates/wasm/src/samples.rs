//! The sample packets of the playground: Ethernet frames built by hand, with correct lengths and
//! checksums.

use avulse_proto::checksum;
use avulse_proto::{Link, ethertype, ip_proto};

/// A sample packet.
pub struct Sample {
    /// Short name, such as "TCP SYN to :443".
    pub name: &'static str,
    /// What the packet is, in one line.
    pub summary: &'static str,
    /// The frame.
    pub bytes: Vec<u8>,
}

const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const GATEWAY_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const HOST: [u8; 4] = [192, 168, 1, 2];
const GATEWAY: [u8; 4] = [192, 168, 1, 1];
const SERVER: [u8; 4] = [93, 184, 215, 14];

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    [&dst[..], &src, &ethertype.to_be_bytes(), payload].concat()
}

fn vlan(id: u16, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    [&id.to_be_bytes()[..], &ethertype.to_be_bytes(), payload].concat()
}

/// An IPv4 header and payload. `frag` is the flags and fragment offset field.
fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, frag: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut v = vec![0x45, 0];
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&0x1c46u16.to_be_bytes());
    v.extend_from_slice(&frag.to_be_bytes());
    v.extend_from_slice(&[64, proto, 0, 0]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[next, 64]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&ack.to_be_bytes());
    v.extend_from_slice(&((5u16 << 12) | flags).to_be_bytes());
    v.extend_from_slice(&[0xfa, 0xf0, 0, 0, 0, 0]);
    v.extend_from_slice(payload);
    v
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

fn finish(mut frame: Vec<u8>) -> Vec<u8> {
    checksum::recalculate(&mut frame, Link::Ethernet);
    frame
}

fn v6(last: u16) -> [u8; 16] {
    let mut a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    a[14..].copy_from_slice(&last.to_be_bytes());
    a
}

const SYN: u16 = 0x002;
const ACK: u16 = 0x010;
const PSH: u16 = 0x008;

/// The samples, in display order.
pub fn samples() -> Vec<Sample> {
    let dns_query = [
        &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..],
        b"\x07example\x03com\x00",
        &[0, 1, 0, 1],
    ]
    .concat();
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.9\r\n\r\n";
    let lldp = [
        &[0x02, 0x07, 0x04][..],
        &GATEWAY_MAC,
        &[0x04, 0x05, 0x05],
        b"eth0",
        &[0x06, 0x02, 0x00, 0x78, 0x00, 0x00],
    ]
    .concat();
    let arp = [
        &[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01][..],
        &HOST_MAC,
        &HOST,
        &[0; 6],
        &GATEWAY,
    ]
    .concat();
    vec![
        Sample {
            name: "TCP SYN to :443",
            summary: "192.168.1.2:40000 → 93.184.215.14:443, a new HTTPS connection",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV4,
                &ipv4(
                    HOST,
                    SERVER,
                    ip_proto::TCP,
                    0x4000,
                    &tcp(40000, 443, 1, 0, SYN, &[]),
                ),
            )),
        },
        Sample {
            name: "HTTP GET",
            summary: "192.168.1.2:40002 → 93.184.215.14:80, GET / HTTP/1.1 with a Host header",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV4,
                &ipv4(
                    HOST,
                    SERVER,
                    ip_proto::TCP,
                    0x4000,
                    &tcp(40002, 80, 1001, 2001, PSH | ACK, http),
                ),
            )),
        },
        Sample {
            name: "DNS query",
            summary: "192.168.1.2:5353 → 192.168.1.1:53, A record for example.com",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV4,
                &ipv4(HOST, GATEWAY, ip_proto::UDP, 0, &udp(5353, 53, &dns_query)),
            )),
        },
        Sample {
            name: "ICMP echo request",
            summary: "ping from 192.168.1.2 to 8.8.8.8, identifier 0x1c46, sequence 1",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV4,
                &ipv4(
                    HOST,
                    [8, 8, 8, 8],
                    ip_proto::ICMP,
                    0,
                    &[
                        8, 0, 0, 0, 0x1c, 0x46, 0, 1, b'a', b'v', b'u', b'l', b's', b'e',
                    ],
                ),
            )),
        },
        Sample {
            name: "ARP request",
            summary: "broadcast: who has 192.168.1.1? Tell 192.168.1.2",
            bytes: eth([0xff; 6], HOST_MAC, ethertype::ARP, &arp),
        },
        Sample {
            name: "VLAN 100, NTP",
            summary: "802.1Q tag 100: 10.0.100.5:123 → 10.0.100.1:123 over UDP",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::VLAN,
                &vlan(
                    100,
                    ethertype::IPV4,
                    &ipv4(
                        [10, 0, 100, 5],
                        [10, 0, 100, 1],
                        ip_proto::UDP,
                        0x4000,
                        &udp(123, 123, &[0x23, 0, 6, 0xe8, 0, 0, 0, 0]),
                    ),
                ),
            )),
        },
        Sample {
            name: "IPv6 TCP SYN-ACK",
            summary: "[2001:db8::1]:443 → [2001:db8::2]:50000, a server accepting a connection",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV6,
                &ipv6(
                    v6(1),
                    v6(2),
                    ip_proto::TCP,
                    &tcp(443, 50000, 7000, 1, SYN | ACK, &[]),
                ),
            )),
        },
        Sample {
            name: "IPv4 fragment",
            summary: "second fragment of a UDP datagram, 192.168.1.2 → 192.168.1.9, offset 1480",
            bytes: finish(eth(
                GATEWAY_MAC,
                HOST_MAC,
                ethertype::IPV4,
                &ipv4(HOST, [192, 168, 1, 9], ip_proto::UDP, 185, &[0x5a; 32]),
            )),
        },
        Sample {
            name: "LLDP",
            summary: "a link-layer discovery frame: not IP, so only the ETHERNET layer sees it",
            bytes: eth(
                [0x01, 0x80, 0xc2, 0, 0, 0x0e],
                GATEWAY_MAC,
                ethertype::LLDP,
                &lldp,
            ),
        },
    ]
}
