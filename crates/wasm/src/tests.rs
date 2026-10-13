use super::*;

fn verdicts(src: &str, outbound: bool) -> Vec<&'static str> {
    let a = analyze(
        src,
        &Context {
            outbound,
            iface: "eth0",
        },
    );
    assert!(
        a.diagnostics.iter().all(|d| d.level != "error"),
        "{src}: {:?}",
        a.diagnostics
    );
    samples()
        .into_iter()
        .zip(a.verdicts)
        .filter(|(_, v)| *v)
        .map(|(s, _)| s.name)
        .collect()
}

#[test]
fn samples_parse_to_their_innermost_header() {
    for s in samples() {
        let p = Packet::parse(&s.bytes, Link::Ethernet);
        let reached = if p.tcp().is_some() {
            "tcp"
        } else if p.udp().is_some() {
            "udp"
        } else if p.icmp().is_some() {
            "icmp"
        } else if p.arp().is_some() {
            "arp"
        } else if p.ipv4().is_some() {
            "ipv4"
        } else {
            "eth"
        };
        let expected = match s.name {
            "TCP SYN to :443" | "HTTP GET" | "IPv6 TCP SYN-ACK" => "tcp",
            "DNS query" | "VLAN 100, NTP" => "udp",
            "ICMP echo request" => "icmp",
            "ARP request" => "arp",
            "IPv4 fragment" => "ipv4",
            "LLDP" => "eth",
            other => panic!("no expectation for {other}"),
        };
        assert_eq!(reached, expected, "{}", s.name);
    }
}

#[test]
fn checksums_are_valid() {
    for s in samples() {
        let mut copy = s.bytes.clone();
        avulse_proto::checksum::recalculate(&mut copy, Link::Ethernet);
        assert_eq!(copy, s.bytes, "{}", s.name);
    }
}

#[test]
fn filters_select_the_expected_samples() {
    assert_eq!(
        verdicts("tcp.flags.syn == 1", false),
        ["TCP SYN to :443", "IPv6 TCP SYN-ACK"]
    );
    assert_eq!(
        verdicts("tcp.payload contains \"Host:\"", false),
        ["HTTP GET"]
    );
    assert_eq!(verdicts("udp.dstport == 53", false), ["DNS query"]);
    assert_eq!(
        verdicts("icmp.type == echo-request", false),
        ["ICMP echo request"]
    );
    assert_eq!(verdicts("vlan.id == 100", false), ["VLAN 100, NTP"]);
    assert_eq!(verdicts("ip.frag_offset > 0", false), ["IPv4 fragment"]);
    assert_eq!(
        verdicts("not ip and not ipv6", false),
        ["ARP request", "LLDP"]
    );
    assert_eq!(verdicts("layer == ethernet", false).len(), samples().len());
    assert_eq!(
        verdicts("iface == \"eth0\" and outbound", false),
        [] as [&str; 0]
    );
    assert_eq!(
        verdicts("outbound and remote.port == 443", true),
        ["TCP SYN to :443"]
    );
    assert_eq!(
        verdicts("tcp.payload matches \"^get /\"", false),
        ["HTTP GET"]
    );
}

#[test]
fn errors_carry_utf16_spans() {
    let a = analyze("\"é\" == tcp.prot", &Context::default());
    assert!(a.verdicts.is_empty() && a.ir.is_none());
    let [d] = &a.diagnostics[..] else {
        panic!("{:?}", a.diagnostics)
    };
    assert_eq!(d.level, "error");
    // `"é" == ` is 7 UTF-16 code units (8 bytes).
    assert_eq!((d.start, d.end), (7, 15));
    assert!(d.rendered.contains("did you mean `tcp.port`?"));
    // The canonical form escapes bytes that are not ASCII.
    assert_eq!(a.canonical.as_deref(), Some(r#""\xc3\xa9" == tcp.prot"#));
}

#[test]
fn warnings_do_not_stop_evaluation() {
    let a = analyze("tcp.flags.syn", &Context::default());
    assert_eq!(a.diagnostics.len(), 1);
    assert_eq!(a.diagnostics[0].level, "warning");
    assert_eq!(a.verdicts.len(), samples().len());
}

#[test]
fn eval_hex_matches_the_cli() {
    let syn = "4500 0028 0001 4000 4006 0000 c0a80102 5db8d70e \
               9c40 01bb 00000001 00000000 5002 ffff 0000 0000";
    let ctx = Context {
        outbound: true,
        iface: "",
    };
    assert_eq!(
        eval_hex("tcp.dstport == 443", syn, Link::Ip, &ctx),
        Ok(true)
    );
    assert_eq!(eval_hex("inbound", syn, Link::Ip, &ctx), Ok(false));
    assert!(eval_hex("tcp", "4g", Link::Ip, &ctx).is_err());
    assert!(eval_hex("tcp", "450", Link::Ip, &ctx).is_err());
    assert!(eval_hex("tcp.prot", syn, Link::Ip, &ctx).is_err());
}

#[test]
fn hex_round_trips() {
    for s in samples() {
        assert_eq!(decode_hex(&encode_hex(&s.bytes)).unwrap(), s.bytes);
    }
    assert_eq!(encode_hex(&[1, 2, 3]), "0102 03");
}
