# Avulse

[![CI](https://github.com/ffalcinelli/avulse/actions/workflows/ci.yml/badge.svg)](https://github.com/ffalcinelli/avulse/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-guide-0a6f93)](https://ffalcinelli.github.io/avulse/guide/)
[![crates.io](https://img.shields.io/crates/v/avulse)](https://crates.io/crates/avulse)
[![PyPI](https://img.shields.io/pypi/v/avulse)](https://pypi.org/project/avulse/)
[![License](https://img.shields.io/badge/license-LGPL--3.0%2B%20OR%20GPL--2.0%2B-blue)](LICENSE)

Divert, modify and re-inject network packets on Linux, Windows and macOS. Avulse covers every
WinDivert feature, adds an Ethernet layer, and uses Wireshark display filters.

> *Avulsion*: a river suddenly abandoning its channel for a new one.

**Status: pre-alpha.** The packet parser, the filter language (native Wireshark syntax and
WinDivert 2.2 syntax), the bytecode verifier and interpreter, and the `avulse` CLI work. The
`avulse` crate and the C library (`libavulse`) divert, sniff, drop and send packets at the
packet layers (`NETWORK`, `NETWORK_FORWARD`, `ETHERNET`), report flows at `FLOW`, report or
refuse socket calls at `SOCKET`, and report handles at `REFLECT`:
- on **Linux**, through TC and cgroup eBPF programs with runtime eBPF code generation;
- on **Windows**, through `avulse.sys` (WFP callouts and an NDIS lightweight filter);
- on **macOS**, through `/dev/bpf` (`SNIFF` and `send` at `NETWORK` and `ETHERNET`) and the
  system extension (`Avulse.app`, awaiting Developer ID signing to run its providers on macOS).

The WinDivert-compatible library (`libavulse_windivert.so` on Linux, `avulse_windivert.dll` on
Windows) passes the pydivert and jdivert test suites unchanged. The crates.io and PyPI packages
only reserve the name until v0.0.1.

**[Website](https://ffalcinelli.github.io/avulse/)** ·
**[Filter playground](https://ffalcinelli.github.io/avulse/#playground)** ·
**[Guide](https://ffalcinelli.github.io/avulse/guide/)** ·
**[Rust API](https://ffalcinelli.github.io/avulse/api/rust/)** ·
**[Roadmap](docs/roadmap.md)**

## Why Avulse

- **Everything WinDivert does**: the NETWORK, NETWORK_FORWARD, FLOW, SOCKET and REFLECT layers,
  flags, priorities and batching, plus a WinDivert-compatible shim for existing programs,
  [pydivert](https://github.com/ffalcinelli/pydivert) and
  [jdivert](https://github.com/ffalcinelli/jdivert).
- **An Ethernet layer**: whole frames, non-IP traffic (ARP, LLDP) and VLAN tags.
- **Wireshark display filters**, with Wireshark 4.6 semantics checked against `tshark`, strict
  types and helpful errors.
- **One engine everywhere**: parsing and matching are `no_std` Rust that never allocates or
  panics while matching, so the same code runs in user space and in kernel drivers.
- **Exact matching in the kernel**: eBPF generated at runtime on Linux, verified bytecode in the
  Windows driver, and the reference evaluator in the macOS system extension.

## Try it

The [playground](https://ffalcinelli.github.io/avulse/#playground) runs the filter engine in your
browser. Or install the CLI:

```console
$ cargo install --locked --git https://github.com/ffalcinelli/avulse avulse-cli
```

A filter is a Wireshark display filter, plus `let` macros and metadata such as the direction:

```filter
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.port in {80, 443, 8000..8100}

outbound and ip.dst not in $lan and $web
```

```console
$ avulse filter check 'tcp.prot == 80'
error: unknown field `tcp.prot`
  |
1 | tcp.prot == 80
  | ^^^^^^^^
  = help: did you mean `tcp.port`?

$ avulse filter explain 'tcp.flags & syn and not tcp.flags & ack'
(and (true (& tcp.flags 2)) (not (true (& tcp.flags 16))))

$ avulse filter fields     # every supported field
```

The [guide](https://ffalcinelli.github.io/avulse/guide/) describes the language, and lists the
[differences from Wireshark](https://ffalcinelli.github.io/avulse/guide/filters/wireshark.html)
and the [fields](https://ffalcinelli.github.io/avulse/guide/reference/fields.html).

## As a library

The crates are not on crates.io yet; use them from Git
([details](https://ffalcinelli.github.io/avulse/guide/libraries/rust.html)).

```rust
use avulse_filter::{Filter, Meta};
use avulse_proto::{Link, Packet};

let filter = Filter::compile("outbound and tcp.dstport in {80, 443}").unwrap();

// IPv4 + TCP SYN from 192.168.1.2:40000 to 93.184.215.14:443.
let bytes = [
    0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 2, 93, 184, 215, 14, //
    0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
];
let packet = Packet::parse(&bytes, Link::Ip);
assert!(filter.matches(&packet, &Meta { outbound: true, ..Meta::default() }));
```

## Workspace

| Crate | State |
| --- | --- |
| [`avulse-proto`](crates/proto) | Zero-copy parsing of Ethernet, VLAN/QinQ, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6; checksums. `no_std`. |
| [`avulse-filter`](crates/filter) | The filter language: parser, type checker, IR, evaluator, bytecode verifier/interpreter, WinDivert 2.2 front-end. `no_std` + `alloc`. |
| [`avulse-abi`](crates/abi) | Shared ABI types (`Address`, `Flags`, `Param`, `Shutdown`, `Stats`, `Syntax`), Windows IOCTL wire format, macOS XPC wire format, WinDivert address conversion. `no_std` + `alloc`. |
| [`avulse`](crates/avulse) | The handle API: handles, flags, parameters, the packet address, and the Linux, Windows and macOS backends. |
| [`avulse-ebpf`](crates/ebpf) | The Linux kernel side: TC programs, the event programs, filter IR to eBPF, the loader. |
| [`avulse-macos-ext`](crates/macos-ext) | The macOS system extension logic (packet chain, held packets, flow/socket/reflect events, XPC handler). |
| [`avulse-capi`](crates/capi) | The C interface, `libavulse`, with the header `include/avulse.h`. |
| [`avulse-windivert-compat`](crates/windivert-compat) | The WinDivert-compatible shim (`libavulse_windivert.so` on Linux, `avulse_windivert.dll` on Windows). |
| [`avulse-cli`](crates/cli) | The `avulse` command: `filter check`, `fmt`, `explain`, `convert`, `eval`, `fields`; `cleanup`. |
| [`avulse-wasm`](crates/wasm) | The engine compiled to WebAssembly, for the playground. |
| [`drivers/windows`](drivers/windows) | The Windows kernel driver (`avulse.sys`: WFP callouts and NDIS lightweight filter) and driver test tool. |
| [`drivers/macos`](drivers/macos) | The macOS system extension bundle (`Avulse.app`: Network Extension providers and XPC service). |
| [`bindings/python`](bindings/python) | The `avulse` PyPI package: a placeholder until Phase 7. |

## Related projects

- [WinDivert](https://reqrypt.org/windivert.html): the Windows packet diverter whose model Avulse
  extends.
- [ebpfdivert](https://github.com/ffalcinelli/ebpfdivert): a WinDivert-compatible library for
  Linux, built on eBPF; Avulse reuses its kernel-side design.
- [pydivert](https://github.com/ffalcinelli/pydivert) and
  [jdivert](https://github.com/ffalcinelli/jdivert): Python and Java bindings for WinDivert and
  ebpfdivert.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the checks and conventions, and
[docs/roadmap.md](docs/roadmap.md) and [docs/implementation-plan.md](docs/implementation-plan.md)
for the design and the next steps.

## License

Dual-licensed under LGPL-3.0-or-later or GPL-2.0-or-later, at your option. See [LICENSE](LICENSE).
