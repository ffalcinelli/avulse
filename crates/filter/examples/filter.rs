//! Compiles a filter and runs it over a few sample packets.
//!
//! ```text
//! cargo run -p avulse-filter --example filter -- 'tcp.dstport == 443 or dns'
//! ```

use avulse_filter::{Filter, Meta};
use avulse_proto::{Link, Packet};

/// Raw IP packets, as the NETWORK layer sees them.
const SAMPLES: &[(&str, &[u8])] = &[
    (
        "TCP SYN 192.168.1.2:40000 -> 93.184.215.14:443",
        &[
            0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 2, 93, 184, 215, 14, //
            0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ],
    ),
    (
        "UDP 10.0.0.1:5353 -> 10.0.0.2:53",
        &[
            0x45, 0, 0, 30, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
            0x14, 0xe9, 0, 53, 0, 10, 0, 0, 0xab, 0xcd,
        ],
    ),
    (
        "ICMP echo request 10.0.0.1 -> 10.0.0.2",
        &[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
            8, 0, 0, 0, 0x12, 0x34, 0, 1,
        ],
    ),
];

fn main() {
    let src = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tcp.flags.syn == 1 or udp.port == 53".into());
    let filter = match Filter::compile(&src) {
        Ok(f) => f,
        Err(e) => {
            eprint!("{}", e.render(&src));
            std::process::exit(2);
        }
    };
    for w in filter.warnings() {
        eprint!("{}", w.render(&src));
    }
    println!("filter: {}", filter.ir());
    let meta = Meta {
        outbound: true,
        ..Meta::default()
    };
    for (name, bytes) in SAMPLES {
        let verdict = filter.matches(&Packet::parse(bytes, Link::Ip), &meta);
        println!("{}  {name}", if verdict { "match   " } else { "no match" });
    }
}
