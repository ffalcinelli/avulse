//! The bytecode: round trips, one rejection per verifier rule, and differential tests against the
//! IR evaluator (the tshark tables over the tshark corpus, and random filters over random packets).

extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use avulse_proto::{Link, Packet, Tcp, ethertype as et, ip_proto as ipp};
use proptest::prelude::*;

use super::frames::*;
use super::tshark;
use crate::bytecode::{
    self, EncodeError, MAX_SIZE, Program, VERSION, VerifyError, VerifyErrorKind as K,
};
use crate::fields::{FIELDS, Ty};
use crate::{Event, Filter, FlowTuple, Layer, Meta};

/// Metadata variants the differential tests run every frame with.
fn metas() -> [Meta<'static>; 3] {
    [
        Meta::default(),
        Meta {
            layer: Layer::Ethernet,
            outbound: true,
            loopback: true,
            impostor: true,
            ifidx: 3,
            subifidx: 1,
            iface: Some("eth0"),
            process_id: Some(42),
            process_name: Some("curl"),
            endpoint_id: Some(7),
            parent_endpoint_id: Some(6),
            ..Meta::default()
        },
        Meta {
            layer: Layer::Flow,
            event: Event::FlowEstablished,
            flow: Some(FlowTuple {
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                local_port: 443,
                remote_port: 51000,
                protocol: ipp::TCP,
            }),
            ..Meta::default()
        },
    ]
}

/// Compiles `src` to bytecode, if it compiles and does not need user space.
fn both(src: &str) -> Option<(Filter, Vec<u8>)> {
    let f = Filter::compile(src).ok()?;
    let bytes = match f.program() {
        Ok(p) => p.to_bytes(),
        Err(EncodeError::UserSpaceOnly) => return None,
        Err(e) => panic!("{src}: {e}"),
    };
    Some((f, bytes))
}

/// The IR evaluator and the bytecode give the same result on `frame`, under every [`metas`], with
/// a fresh register file and with one reused from the earlier runs.
fn agree(src: &str, f: &Filter, bytes: &[u8], frame: &[u8], link: Link) -> Result<(), String> {
    let program = bytecode::verify(bytes).map_err(|e| format!("{src}: {e}"))?;
    let packet = Packet::parse(frame, link);
    let metas = metas();
    let mut regs = bytecode::Registers::new();
    for meta in &metas {
        let (ir, bc) = (f.matches(&packet, meta), program.matches(&packet, meta));
        let reused = program.matches_in(&mut regs, &packet, meta);
        if ir != bc || bc != reused {
            return Err(format!(
                "{src}\n  frame {frame:02x?} ({link:?}), {meta:?}\n  IR {ir}, bytecode {bc}\n{}",
                f.program().unwrap()
            ));
        }
    }
    Ok(())
}

#[test]
fn field_ids_are_registry_indexes() {
    for (i, d) in FIELDS.iter().enumerate() {
        assert_eq!(d.field as usize, i, "{}", d.name);
    }
}

#[test]
fn round_trips() {
    for src in [
        "tcp.port in {80 443 8000..8100} and not ip.src == 10.0.0.0/8",
        "eth.addr == 00:11:22:33:44:55 or vlan.id#2 == 4 xor @ip.ttl == 40",
        "tcp.payload[0:3,5-6] contains \"GE\" && len(udp) > 8",
        "max(tcp.srcport, tcp.dstport * 2, -1) % 7 != abs(-3)",
        "upper(iface) == \"ETH0\" and count(ip.addr) == 2 and all ip.addr != 1.2.3.4",
        "ipv6.addr == 2001:db8::/32 and @tcp.port#1 == 00:50 and ip.src & 255.0.0.0 == 10.0.0.0",
        "not (tcp.flags.syn xor (udp or not icmp)) and frame[-2:] == 00:00",
    ] {
        let program = Filter::compile(src).unwrap().program().unwrap();
        let bytes = program.to_bytes();
        let back = Program::from_bytes(&bytes).unwrap_or_else(|e| panic!("{src}: {e}"));
        assert_eq!(back, program, "{src}");
        assert_eq!(back.to_string(), program.to_string(), "{src}");
        assert_eq!(back.to_bytes(), bytes, "{src}");
    }
}

#[test]
fn disassembly() {
    let p = Filter::compile("tcp.dstport in {80 443} and not ip.src == 10.0.0.0/8")
        .unwrap()
        .program()
        .unwrap();
    assert_eq!(
        p.to_string(),
        "0  field    r0, tcp.dstport\n\
         1  member   any_in r0, {80 443}\n\
         2  jf       7\n\
         3  field    r0, ip.src\n\
         4  lit      r1, 10.0.0.0/8\n\
         5  cmp      any_eq r0, r1\n\
         6  not\n"
    );
}

#[test]
fn encode_errors() {
    #[cfg(feature = "regex")]
    assert_eq!(
        Filter::compile("tcp.payload matches \"x\"")
            .unwrap()
            .program(),
        Err(EncodeError::UserSpaceOnly)
    );
    // Each `xor` on the left needs a boolean register.
    let deep = "tcp xor (".repeat(9) + "udp" + &")".repeat(9);
    let deep = Filter::compile(&deep).unwrap();
    assert_eq!(deep.program(), Err(EncodeError::TooDeep));
    // Each nested `+` needs a value register.
    let nested = "tcp.len == ".to_string() + &"{1 + ".repeat(17) + "tcp.len" + &"}".repeat(17);
    assert_eq!(
        Filter::compile(&nested).unwrap().program(),
        Err(EncodeError::TooDeep)
    );
    let big = (0..4000)
        .map(|i| format!("tcp.port == {i}"))
        .collect::<Vec<_>>()
        .join(" or ");
    assert_eq!(
        Filter::compile(&big).unwrap().program(),
        Err(EncodeError::TooLarge)
    );
}

// Hand-made programs for the verifier tests, built from the format in `bytecode`'s documentation.
const LIT: u8 = 1;
const FIELD: u8 = 2;
const LAYER: u8 = 3;
const RAW: u8 = 4;
const SLICE: u8 = 5;
const ARITH: u8 = 7;
const CONST: u8 = 32;
const EXISTS: u8 = 33;
const CMP: u8 = 35;
const MEMBER: u8 = 36;
const SAVEB: u8 = 39;
const JT: u8 = 48;
const JMP: u8 = 50;

fn insn(op: u8, a: u8, b: u8, c: u8, imm: u32) -> [u8; 8] {
    let i = imm.to_le_bytes();
    [op, a, b, c, i[0], i[1], i[2], i[3]]
}

fn program(insns: &[[u8; 8]], pool: &[u8]) -> Vec<u8> {
    let mut v = b"AVBC".to_vec();
    v.extend_from_slice(&VERSION.to_le_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&(insns.len() as u32).to_le_bytes());
    v.extend_from_slice(&(pool.len() as u32).to_le_bytes());
    insns.iter().for_each(|i| v.extend_from_slice(i));
    v.extend_from_slice(pool);
    v
}

fn rejects(bytes: &[u8]) -> VerifyError {
    match bytecode::verify(bytes) {
        Ok(_) => panic!("accepted {bytes:02x?}"),
        Err(e) => e,
    }
}

fn header_error(bytes: &[u8]) -> K {
    let e = rejects(bytes);
    assert_eq!(e.at, None);
    e.kind
}

/// The error of a program whose instruction 0 is `i`.
fn insn_error(i: [u8; 8], pool: &[u8]) -> K {
    let e = rejects(&program(&[i], pool));
    assert_eq!(e.at, Some(0), "{e}");
    e.kind
}

/// A ranges entry: `(start, kind, end)` each.
fn ranges(r: &[(i64, u8, i64)]) -> Vec<u8> {
    let mut v = vec![16, r.len() as u8];
    for (s, k, e) in r {
        v.extend_from_slice(&s.to_le_bytes());
        v.push(*k);
        v.extend_from_slice(&e.to_le_bytes());
    }
    v
}

#[test]
fn verifier_accepts_well_formed_programs() {
    let mut pool = vec![1];
    pool.extend_from_slice(&80u64.to_le_bytes());
    let ok = program(
        &[
            insn(FIELD, 0, 0, 0, 0),
            insn(LIT, 1, 0, 0, 0),
            insn(CMP, 0, 0, 1, 0),
            insn(JT, 0, 0, 0, 4),
        ],
        &pool,
    );
    bytecode::verify(&ok).unwrap();
}

#[test]
fn verifier_rejects_bad_headers() {
    let ok = program(&[insn(CONST, 0, 0, 0, 1)], &[]);
    bytecode::verify(&ok).unwrap();
    let with = |at: usize, b: u8| {
        let mut v = ok.clone();
        v[at] = b;
        v
    };
    assert_eq!(header_error(&with(0, b'X')), K::BadMagic);
    assert_eq!(header_error(&with(4, VERSION as u8 + 1)), K::BadVersion);
    assert_eq!(header_error(&with(6, 1)), K::BadFlags);
    assert_eq!(header_error(&with(12, 1)), K::BadLength);
    assert_eq!(header_error(&ok[..ok.len() - 1]), K::BadLength);
    assert_eq!(header_error(&ok[..10]), K::BadLength);
    assert_eq!(header_error(&[ok.as_slice(), &[0]].concat()), K::BadLength);
    assert_eq!(header_error(&program(&[], &[])), K::Empty);
    // A huge instruction count must not overflow the length check.
    let mut huge = ok.clone();
    huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(header_error(&huge), K::BadLength);
    let pool = vec![0; MAX_SIZE];
    assert_eq!(
        header_error(&program(&[insn(CONST, 0, 0, 0, 1)], &pool)),
        K::TooLarge
    );
}

#[test]
fn verifier_rejects_bad_instructions() {
    assert_eq!(insn_error(insn(0, 0, 0, 0, 0), &[]), K::BadOpcode);
    assert_eq!(insn_error(insn(14, 0, 0, 0, 0), &[]), K::BadOpcode);
    assert_eq!(insn_error(insn(CONST, 1, 0, 0, 1), &[]), K::ReservedOperand);
    assert_eq!(insn_error(insn(FIELD, 0, 1, 0, 0), &[]), K::ReservedOperand);
    assert_eq!(
        insn_error(insn(EXISTS, 0, 0, 0, 1), &[]),
        K::ReservedOperand
    );
    assert_eq!(insn_error(insn(FIELD, 16, 0, 0, 0), &[]), K::BadRegister);
    assert_eq!(insn_error(insn(CMP, 0, 0, 16, 0), &[]), K::BadRegister);
    assert_eq!(insn_error(insn(SAVEB, 8, 0, 0, 0), &[]), K::BadBoolRegister);
    let fields = FIELDS.len() as u32;
    assert_eq!(insn_error(insn(FIELD, 0, 0, 0, fields), &[]), K::BadField);
    let [lo, hi] = (fields as u16).to_le_bytes();
    assert_eq!(insn_error(insn(RAW, 0, lo, hi, u32::MAX), &[]), K::BadField);
    assert_eq!(insn_error(insn(CONST, 0, 0, 0, 2), &[]), K::BadOperand);
    assert_eq!(insn_error(insn(ARITH, 0, 0, 1, 5), &[]), K::BadOperand);
    assert_eq!(insn_error(insn(CMP, 6, 0, 1, 0), &[]), K::BadOperand);
    assert_eq!(insn_error(insn(CMP, 16, 0, 1, 0), &[]), K::BadOperand);
    assert_eq!(insn_error(insn(JT, 0, 0, 0, 0), &[]), K::BadJump);
    assert_eq!(insn_error(insn(JT, 0, 0, 0, 2), &[]), K::BadJump);
    assert_eq!(insn_error(insn(JMP, 0, 0, 0, 0), &[]), K::BadJump);
    assert_eq!(insn_error(insn(JMP, 1, 0, 0, 1), &[]), K::ReservedOperand);
    // A jump back, at the second instruction.
    let back = program(&[insn(CONST, 0, 0, 0, 1), insn(JT, 0, 0, 0, 0)], &[]);
    assert_eq!(
        rejects(&back),
        VerifyError {
            kind: K::BadJump,
            at: Some(1)
        }
    );
}

#[test]
fn verifier_rejects_bad_constants() {
    let lit = |pool: &[u8]| insn_error(insn(LIT, 0, 0, 0, 0), pool);
    assert_eq!(
        insn_error(insn(LIT, 0, 0, 0, 2), &[0, 1]),
        K::ConstantOutOfBounds
    );
    assert_eq!(
        insn_error(insn(LIT, 0, 0, 0, u32::MAX), &[0, 1]),
        K::ConstantOutOfBounds
    );
    assert_eq!(lit(&[16, 1]), K::ConstantKind);
    assert_eq!(lit(&[99]), K::ConstantKind);
    assert_eq!(lit(&[0, 2]), K::MalformedConstant);
    assert_eq!(lit(&[1, 0, 0]), K::MalformedConstant);
    assert_eq!(lit(&[3, 10, 0, 0, 1, 33]), K::MalformedConstant);
    assert_eq!(lit(&[4, 0]), K::MalformedConstant);
    assert_eq!(lit(&[6, 5, 0, b'a']), K::MalformedConstant);
    let slice = |pool: &[u8]| insn_error(insn(SLICE, 0, 0, 0, 0), pool);
    assert_eq!(slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), K::ConstantKind);
    assert_eq!(slice(&[16, 0]), K::MalformedConstant);
    assert_eq!(slice(&ranges(&[(0, 3, 1)])), K::MalformedConstant);
    assert_eq!(slice(&ranges(&[(0, 0, 0)])), K::MalformedConstant);
    assert_eq!(slice(&ranges(&[(0, 2, 1)])), K::MalformedConstant);
    let r = ranges(&[(0, 0, 1)]);
    assert_eq!(slice(&r[..r.len() - 1]), K::MalformedConstant);
    let [lo, hi] = 0u16.to_le_bytes();
    assert_eq!(
        insn_error(insn(LAYER, 0, lo, hi, 0), &[17, 0, 0]),
        K::ConstantKind
    );
    let member = |pool: &[u8]| insn_error(insn(MEMBER, 0, 0, 0, 0), pool);
    assert_eq!(member(&ranges(&[(0, 0, 1)])), K::ConstantKind);
    assert_eq!(member(&[17, 2, 0, 0, 0, 1]), K::MalformedConstant);
    assert_eq!(member(&[17, 1, 0, 2, 0, 1]), K::MalformedConstant);
    assert_eq!(member(&[17, 1, 0, 1, 0, 1]), K::MalformedConstant);
    assert_eq!(member(&[17, 1]), K::MalformedConstant);
    bytecode::verify(&program(
        &[insn(MEMBER, 3, 0, 0, 0)],
        &[17, 2, 0, 0, 0, 1, 1, 0, 0, 0, 1],
    ))
    .unwrap();
}

/// A program running past its last instruction, or reading registers it never wrote, is harmless.
#[test]
fn unwritten_registers_are_empty() {
    let p = program(&[insn(EXISTS, 0, 15, 0, 0)], &[]);
    let frame = https_syn();
    let v = bytecode::verify(&p).unwrap();
    let packet = Packet::parse(&frame, Link::Ethernet);
    let meta = Meta::default();
    assert!(!v.matches(&packet, &meta));
    // Not even when an earlier run left a value there.
    let port = FIELDS.iter().position(|d| d.name == "tcp.port").unwrap() as u32;
    let w = program(
        &[insn(FIELD, 15, 0, 0, port), insn(EXISTS, 0, 15, 0, 0)],
        &[],
    );
    let w = bytecode::verify(&w).unwrap();
    let mut regs = bytecode::Registers::new();
    assert!(w.matches_in(&mut regs, &packet, &meta));
    assert!(!v.matches_in(&mut regs, &packet, &meta));
}

/// Every table filter of the tshark comparison, over its whole corpus: the IR evaluator and the
/// bytecode agree. This needs no tshark.
#[test]
fn bytecode_agrees_on_the_tshark_tables() {
    let eth = tshark::corpus();
    let raw = tshark::raw_corpus(&eth);
    let filters = tshark::AGREE
        .iter()
        .chain(tshark::OUTER)
        .chain(tshark::DIVERGENCES.iter().map(|(f, ..)| f))
        .chain(tshark::EXTENSIONS)
        .copied()
        .chain(tshark::presence_filters());
    let mut n = 0;
    for src in filters {
        let Some((f, bytes)) = both(src) else {
            continue;
        };
        n += 1;
        for (link, corpus) in [(Link::Ethernet, &eth), (Link::Ip, &raw)] {
            for (_, frame) in corpus {
                agree(src, &f, &bytes, frame, link).unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }
    assert!(n > 300, "only {n} filters compiled");
}

// Random filters over random packets.

/// A literal of type `ty`, biased towards values the generated packets hold.
fn literal(ty: Ty) -> BoxedStrategy<String> {
    let s = |v: &[&'static str]| proptest::sample::select(v.to_vec()).prop_map(String::from);
    match ty {
        Ty::Bool => s(&["1", "0", "true", "false", "True"]).boxed(),
        Ty::Uint(_) | Ty::Int => prop_oneof![
            s(&[
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "8",
                "17",
                "20",
                "40",
                "64",
                "80",
                "443",
                "0x800",
                "0x86dd",
                "0x12",
                "1000",
                "2000",
                "51000",
                "65535",
                "4294967295",
                "-1"
            ]),
            any::<u16>().prop_map(|v| v.to_string()),
        ]
        .boxed(),
        Ty::Ipv4 => s(&[
            "10.0.0.1",
            "192.168.1.2",
            "10.0.0.0/8",
            "192.168.0.0/16",
            "0.0.0.0/0",
            "1.2.3.4",
        ])
        .boxed(),
        Ty::Ipv6 => s(&["fe80::1", "2001:db8::2", "2001:db8::/32", "::/0", "::1"]).boxed(),
        Ty::Ip => prop_oneof![literal(Ty::Ipv4), literal(Ty::Ipv6)].boxed(),
        Ty::Ether => s(&[
            "00:11:22:33:44:55",
            "66:77:88:99:aa:bb",
            "ff:ff:ff:ff:ff:ff",
            "00:11:22:00:00:00",
        ])
        .boxed(),
        Ty::Bytes | Ty::Proto => prop_oneof![
            s(&[
                "\"GET\"", "\"hi\"", "\"ping\"", "\"\"", "45", "00:50", "c0:a8", "08:00"
            ]),
            proptest::collection::vec(
                prop_oneof![Just(0u8), Just(0x45), Just(0x50), any::<u8>()],
                1..4
            )
            .prop_map(|b| b
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(":")),
        ]
        .boxed(),
        Ty::Str => s(&["\"eth0\"", "\"ETH0\"", "\"lo\"", "\"curl\"", "\"\""]).boxed(),
    }
}

fn field() -> impl Strategy<Value = &'static crate::fields::FieldDef> {
    proptest::sample::select(FIELDS.iter().collect::<Vec<_>>())
}

const ORDERED: &[&str] = &["<", "<=", ">", ">="];
const EQUALITY: &[&str] = &["==", "!=", "===", "!==", "~="];

/// A literal for field `d`: of its type, or one of its symbolic constants.
fn literal_for(d: &'static crate::fields::FieldDef) -> BoxedStrategy<String> {
    if d.consts.is_empty() {
        literal(d.ty)
    } else {
        let names: Vec<String> = d.consts.iter().map(|(n, _)| n.to_string()).collect();
        prop_oneof![3 => literal(d.ty), 1 => proptest::sample::select(names)].boxed()
    }
}

/// A comparison of a field (a slice of it, for a protocol) with a literal of its type.
fn comparison() -> impl Strategy<Value = String> {
    field().prop_flat_map(|d| {
        let ops: Vec<&str> = if d.ty.is_ordered() || d.ty == Ty::Proto {
            EQUALITY.iter().chain(ORDERED).copied().collect()
        } else {
            EQUALITY.to_vec()
        };
        let (name, lit) = match d.ty {
            Ty::Proto => (format!("{}[0:2]", d.name), literal(Ty::Bytes)),
            _ => (d.name.to_string(), literal_for(d)),
        };
        (
            proptest::sample::select(vec!["", "any ", "all "]),
            proptest::sample::select(ops),
            lit,
        )
            .prop_map(move |(q, op, lit)| format!("{q}{name} {op} {lit}"))
    })
}

/// Set membership, with items of the field's type.
fn membership() -> impl Strategy<Value = String> {
    field().prop_flat_map(|d| {
        let item = if d.ty.is_ordered() {
            prop_oneof![
                3 => literal_for(d),
                1 => (literal_for(d), literal_for(d)).prop_map(|(a, b)| format!("{a}..{b}")),
            ]
            .boxed()
        } else {
            literal_for(d)
        };
        (
            proptest::sample::select(vec!["", "all "]),
            proptest::sample::select(vec!["in", "not in"]),
            proptest::collection::vec(item, 1..5),
        )
            .prop_map(move |(q, op, s)| format!("{q}{} {op} {{{}}}", d.name, s.join(" ")))
    })
}

/// A numeric expression over integer fields.
fn arith() -> impl Strategy<Value = String> {
    let ints: Vec<&str> = FIELDS
        .iter()
        .filter(|d| matches!(d.ty, Ty::Uint(_)))
        .map(|d| d.name)
        .collect();
    let leaf = prop_oneof![
        proptest::sample::select(ints.clone()).prop_map(String::from),
        literal(Ty::Uint(16)),
        proptest::sample::select(vec!["len(tcp.payload)", "count(ip.addr)", "len(frame)"])
            .prop_map(String::from),
    ];
    leaf.prop_recursive(3, 8, 3, |inner| {
        prop_oneof![
            (
                inner.clone(),
                proptest::sample::select(vec!["+", "-", "*", "/", "%", "&"]),
                inner.clone()
            )
                .prop_map(|(a, op, b)| format!("{{{a} {op} {b}}}")),
            inner.clone().prop_map(|a| format!("-{a}")),
            inner.clone().prop_map(|a| format!("abs({a})")),
            proptest::collection::vec(inner, 1..4).prop_map(|v| format!(
                "{}({})",
                if v.len() % 2 == 0 { "max" } else { "min" },
                v.join(", ")
            )),
        ]
    })
}

/// A byte-valued expression: a field with bytes, a slice of it, `@field`, or a case-folded
/// string.
fn bytes_value() -> impl Strategy<Value = String> {
    let byte_fields: Vec<&str> = FIELDS
        .iter()
        .filter(|d| d.ty.is_bytes())
        .map(|d| d.name)
        .collect();
    let range = (-6i64..40, 0u8..3, 1i64..6).prop_map(|(s, k, n)| match k {
        0 => format!("{s}:{n}"),
        1 if s >= 0 => format!("{s}-{}", s + n - 1),
        _ => format!("{s}:"),
    });
    let f = proptest::sample::select(byte_fields);
    prop_oneof![
        f.clone().prop_map(String::from),
        (f.clone(), proptest::collection::vec(range, 1..3))
            .prop_map(|(f, r)| format!("{f}[{}]", r.join(","))),
        field().prop_map(|d| format!("@{}", d.name)),
        (
            proptest::sample::select(vec!["upper", "lower"]),
            proptest::sample::select(vec!["iface", "process.name", "frame.interface_name"])
        )
            .prop_map(|(c, f)| format!("{c}({f})")),
        (
            field(),
            proptest::sample::select(vec!["#1", "#2", "#-1", "#1-2", "#[1:]"])
        )
            .prop_map(|(d, l)| format!("{}{l}", d.name)),
    ]
}

/// One test.
fn atom() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => comparison(),
        1 => field().prop_map(|d| d.name.to_string()),
        1 => membership(),
        1 => (
            bytes_value(),
            proptest::sample::select(vec!["contains", "all contains", "==", "!=", "<", ">="]),
            prop_oneof![literal(Ty::Bytes), literal(Ty::Str), bytes_value()]
        )
            .prop_map(|(a, op, b)| match op.strip_prefix("all ") {
                Some(op) => format!("all {a} {op} {b}"),
                None => format!("{a} {op} {b}"),
            }),
        1 => (
            arith(),
            proptest::sample::select(EQUALITY.iter().chain(ORDERED).copied().collect::<Vec<_>>()),
            arith()
        )
            .prop_map(|(a, op, b)| format!("{a} {op} {b}")),
        1 => prop_oneof![
            literal(Ty::Uint(8)).prop_map(|m| format!("tcp.flags & {m}")),
            (literal(Ty::Ipv4), literal(Ty::Ipv4)).prop_map(|(m, a)| format!("ip.src & {m} == {a}")),
            (literal(Ty::Ether), literal(Ty::Ether)).prop_map(|(m, a)| format!("eth.addr & {m} == {a}")),
            (literal(Ty::Bytes), literal(Ty::Bytes)).prop_map(|(m, a)| format!("tcp.payload & {m} == {a}")),
        ],
    ]
}

fn filter() -> impl Strategy<Value = String> {
    atom().prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            (
                inner.clone(),
                proptest::sample::select(vec!["and", "or", "xor", "&&", "||", "^^"]),
                inner.clone()
            )
                .prop_map(|(a, op, b)| format!("({a}) {op} ({b})")),
            inner.prop_map(|a| format!("not ({a})")),
        ]
    })
}

/// A frame from the builders with random parameters, then perhaps truncated and with bytes
/// flipped.
fn frame() -> impl Strategy<Value = (Vec<u8>, Link)> {
    let ports = prop_oneof![Just(80u16), Just(443), Just(53), Just(51000), any::<u16>()];
    let payload = prop_oneof![
        Just(b"GET / HTTP/1.1\r\n".to_vec()),
        Just(b"hi".to_vec()),
        Just(Vec::new()),
        proptest::collection::vec(any::<u8>(), 0..24),
    ];
    let l4 = (0u8..6, ports.clone(), ports, any::<u16>(), payload).prop_map(
        |(kind, sp, dp, bits, body)| match kind {
            0 | 1 => (ipp::TCP, tcp(sp, dp, bits & 0xfff, &body)),
            2 => (
                ipp::TCP,
                tcp_with(sp, dp, bits & 0x3f | Tcp::SYN, &[2, 4, 5, 0xb4], &body),
            ),
            3 => (ipp::UDP, udp(sp, dp, &body)),
            4 => (
                ipp::ICMP,
                icmp((bits >> 8) as u8 % 20, 0, [0, 7, 0, 9], &body),
            ),
            _ => (
                ipp::ICMPV6,
                icmp(128 + (bits as u8 % 8), 0, [0, 1, 0, 2], &body),
            ),
        },
    );
    let net = (0u8..6, l4, any::<u16>()).prop_map(|(kind, (proto, l4), bits)| match kind {
        0 | 1 => (et::IPV4, ipv4(proto, &l4)),
        2 => (
            et::IPV4,
            ipv4_with(
                V4 {
                    tos: bits as u8,
                    frag: bits & 0xe00f,
                    options: if bits & 0x100 != 0 {
                        &[1, 1, 1, 0]
                    } else {
                        &[]
                    },
                },
                proto,
                &l4,
            ),
        ),
        3 => (et::IPV6, ipv6(proto, &l4)),
        4 => (
            et::IPV6,
            ipv6(
                ipp::IPV6_FRAG,
                &ipv6_frag(proto, bits & 7, bits & 8 != 0, &l4),
            ),
        ),
        _ => (et::IPV6, ipv6(ipp::HOPOPT, &ipv6_hbh(proto, &l4))),
    });
    let tags = prop_oneof![
        3 => Just(Vec::new()),
        1 => any::<u16>().prop_map(|t| vec![(et::VLAN, t)]),
        1 => (any::<u16>(), any::<u16>()).prop_map(|(a, b)| vec![(et::QINQ, a), (et::VLAN, b)]),
        1 => (any::<u16>(), any::<u16>()).prop_map(|(a, b)| vec![(et::VLAN, a), (et::VLAN, b)]),
    ];
    let built = (net, tags, 0u8..10).prop_map(|((ety, l3), tags, kind)| match kind {
        0 => (arp_request(), Link::Ethernet),
        1 if tags.is_empty() => (l3, Link::Ip),
        _ => (eth_tpids(ety, &tags, &l3), Link::Ethernet),
    });
    (
        built,
        proptest::option::weighted(0.2, any::<prop::sample::Index>()),
        proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..3),
    )
        .prop_map(|((mut f, link), cut, flips)| {
            if let Some(cut) = cut {
                f.truncate(cut.index(f.len() + 1));
            }
            if !f.is_empty() {
                for (at, b) in flips {
                    let i = at.index(f.len());
                    f[i] = b;
                }
            }
            (f, link)
        })
}

proptest! {
    /// The IR evaluator and the bytecode agree on random filters over random packets. Raise
    /// `PROPTEST_CASES` for a longer run.
    #[test]
    fn bytecode_agrees_with_the_evaluator(
        src in filter(),
        frames in proptest::collection::vec(frame(), 8),
    ) {
        if let Some((f, bytes)) = both(&src) {
            for (frame, link) in &frames {
                if let Err(e) = agree(&src, &f, &bytes, frame, *link) {
                    return Err(TestCaseError::fail(e));
                }
            }
        }
    }
}

/// The random filters compile often enough for the property test to mean something.
#[test]
fn random_filters_mostly_compile() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let n = 500;
    let ok = (0..n)
        .filter(|_| {
            let src = filter().new_tree(&mut runner).unwrap().current();
            both(&src).is_some()
        })
        .count();
    assert!(ok * 2 > n, "only {ok} of {n} random filters compiled");
}
