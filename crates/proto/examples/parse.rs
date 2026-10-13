//! Parses a packet given in hex and prints its headers.
//!
//! ```text
//! cargo run -p avulse-proto --example parse -- [--ip] [HEX]
//! ```
//!
//! Without `HEX`, it parses a built-in Ethernet + IPv4 + TCP SYN frame.

use avulse_proto::{Link, Network, Packet, Transport};

/// Ethernet + IPv4 + TCP SYN from 10.0.0.1:40000 to 192.0.2.7:443.
const FRAME: &str = "020000000002 020000000001 0800
    4500 0028 0001 4000 4006 0000 0a000001 c0000207
    9c40 01bb 00000001 00000000 5002 ffff 0000 0000";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let link = if args.iter().any(|a| a == "--ip") {
        Link::Ip
    } else {
        Link::Ethernet
    };
    let hex = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map_or(FRAME, String::as_str);
    let bytes = match decode_hex(hex) {
        Some(b) => b,
        None => {
            eprintln!("invalid hex");
            std::process::exit(2);
        }
    };

    let pkt = Packet::parse(&bytes, link);
    if let Some(eth) = pkt.eth() {
        println!("ethernet  {} -> {}", eth.src(), eth.dst());
    }
    for tag in pkt.vlans() {
        println!("vlan      id {} priority {}", tag.id(), tag.priority());
    }
    match pkt.network() {
        Network::Arp(arp) => println!("arp       opcode {}", arp.opcode()),
        Network::Ipv4(ip) => println!("ipv4      {} -> {} ttl {}", ip.src(), ip.dst(), ip.ttl()),
        Network::Ipv6(ip) => println!("ipv6      {} -> {}", ip.src(), ip.dst()),
        Network::None => {}
    }
    if let Some(frag) = pkt.fragment() {
        println!("fragment  offset {} more {}", frag.offset * 8, frag.more);
    }
    match pkt.transport() {
        Transport::Tcp(t) => println!(
            "tcp       {} -> {} flags {:#05x}",
            t.src_port(),
            t.dst_port(),
            t.flags()
        ),
        Transport::Udp(u) => println!("udp       {} -> {}", u.src_port(), u.dst_port()),
        Transport::Icmp(i) => println!("icmp      type {} code {}", i.icmp_type(), i.code()),
        Transport::Icmpv6(i) => println!("icmpv6    type {} code {}", i.icmp_type(), i.code()),
        Transport::None => {}
    }
    println!("payload   {} bytes", pkt.payload().len());
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    if s.bytes()
        .any(|c| !c.is_ascii_hexdigit() && !c.is_ascii_whitespace() && c != b':')
        || !digits.len().is_multiple_of(2)
    {
        return None;
    }
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}
