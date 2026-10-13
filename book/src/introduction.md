# Introduction

**Avulse** diverts network packets to user space, where a program can inspect, drop, modify or
re-inject them, on Linux, Windows and macOS. It aims to cover every feature of
[WinDivert](https://reqrypt.org/windivert.html), and to go beyond it:

- **An Ethernet layer.** Besides IP packets, flows, sockets and handle events, Avulse adds a layer
  that sees whole frames, non-IP traffic (ARP, LLDP) and VLAN tags included.
- **Wireshark display filters.** Filters use the language people already know from Wireshark and
  can test with `tshark`. A filter that Wireshark accepts and Avulse compiles selects the same
  packets.
- **One engine everywhere.** Packet parsing and filter evaluation live in two `no_std` Rust crates
  that never allocate or panic while matching, so the same code runs in user space, in the
  Windows driver and in the macOS system extension. One engine means one set of semantics.
- **A WinDivert-compatible shim**, so that existing WinDivert programs and the
  [pydivert](https://github.com/ffalcinelli/pydivert) and
  [jdivert](https://github.com/ffalcinelli/jdivert) bindings can move over without a rewrite.

> *Avulsion*: a river suddenly abandoning its channel for a new one.

## Status

Avulse is **pre-alpha**. It cannot capture packets yet. What works today:

| Part | State |
| --- | --- |
| `avulse-proto` | Zero-copy parsing of Ethernet, VLAN/QinQ, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6; checksums. |
| `avulse-filter` | The filter language: parser, type checker, IR and evaluator, validated against `tshark`. |
| `avulse` CLI | `avulse filter check`, `fmt`, `explain`, `eval` and `fields`. |
| Capture backends | Planned: eBPF on Linux, a WFP/NDIS driver on Windows, a Network Extension on macOS. |

The [design and roadmap](project/design.md) chapter has the plan. You can try the filter language
right now in the [playground](https://ffalcinelli.github.io/avulse/#playground), which runs the
real engine compiled to WebAssembly, or with the [command-line tool](getting-started/install.md).

## How this guide is organized

- **Getting started** installs the CLI and walks through checking and testing a filter.
- **The filter language** describes the syntax and the semantics, then lists where Avulse differs
  from Wireshark and the limits of its evaluator.
- **Reference** lists every field and every command.
- **Libraries** shows how to use the Rust crates, and where the Python package stands.
- **Project** covers the architecture, the roadmap and how to contribute.

The API documentation of the crates is generated separately:
[Rust API](https://ffalcinelli.github.io/avulse/api/rust/) and
[Python API](https://ffalcinelli.github.io/avulse/api/python/).
