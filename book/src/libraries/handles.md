# Handles and addresses

> **Preview.** Only Linux has a backend so far, and it only receives: handles divert, sniff or
> drop packets, but `send` returns `Error::Unsupported` until injection lands. Elsewhere,
> `Handle::open` returns `Error::Unsupported`. The API may still change before version 0.1.

The model is WinDivert's. You open a **handle** at a **layer**, with a filter, a priority and
flags. It receives the packets or events that the filter matches, each with an **address**. At
the packet layers it can also send packets: the ones it received, modified or not, or new ones.

```rust,ignore
use avulse::{Flags, Handle, Layer, MAX_PACKET_LEN};

// Divert outbound HTTP, and send it on unchanged.
let handle = Handle::open("outbound and tcp.dstport == 80", Layer::Network, 0, Flags::NONE)?;
let mut buf = vec![0; MAX_PACKET_LEN];
loop {
    let (len, addr) = handle.recv(&mut buf)?;
    handle.send(&buf[..len], &addr)?;
}
```

`Handle::open_windivert` takes a [WinDivert filter](../filters/windivert.md) instead.
`OpenOptions` has the rest of the options, such as capturing only on some interfaces:

```rust,ignore
let handle = OpenOptions::new()
    .priority(100)
    .flags(Flags::SNIFF)
    .interfaces(["eth0"])
    .open("arp or vlan", Layer::Ethernet)?;
```

## Layers

| Layer | What the handle sees | Packets start with |
| --- | --- | --- |
| `Network` | IP packets to and from this host | the IP header |
| `NetworkForward` | IP packets this host forwards | the IP header |
| `Ethernet` | every frame on the interfaces, non-IP included (an Avulse addition) | the Ethernet header |
| `Flow` | flows established and deleted (events, no packet) | |
| `Socket` | bind, connect, listen, accept and close (events) | |
| `Reflect` | other handles opening and closing (events) | |

## Flags

The flags have WinDivert's values and rules.

| Flag | Effect |
| --- | --- |
| (none) | Divert: matching packets leave their path until the handle sends them back. |
| `SNIFF` | Receive copies; the packets go on. |
| `DROP` | Drop matching packets; receive nothing. Excludes `SNIFF`. |
| `RECV_ONLY` | The handle cannot send. Required with `SNIFF` at `Flow` and `Reflect`, and alone at `Socket`. |
| `SEND_ONLY` | The handle captures nothing. Excludes `RECV_ONLY`. |
| `NO_INSTALL` | Fail if the driver or programs are not installed already. |
| `FRAGMENTS` | Also capture IP fragments other than the first. |

The **priority** goes from -30000 to 30000; handles with a higher priority see packets first, and
0 places a handle after every handle open so far. The **queue parameters** (`Param::QueueLength`,
`QueueTime` and `QueueSize`) bound how many packets, for how long and how many bytes wait for
`recv`, with WinDivert's ranges and defaults.

## The address

An `Address` has explicit fields instead of WinDivert's 80-byte union. It is `#[repr(C)]` and
versioned (`ADDRESS_VERSION`), so the C API can expose it as it is.

| Field | Meaning |
| --- | --- |
| `timestamp` | When the packet was seen, in nanoseconds of a monotonic clock |
| `layer`, `event` | The handle's layer, and what happened (`Event::Packet` at the packet layers) |
| `outbound`, `loopback`, `impostor`, `sniffed` | Direction; loopback interface; injected by another handle; received as a copy |
| `ipv6` | The packet is IPv6 |
| `ip_checksum`, `tcp_checksum`, `udp_checksum` | The checksum is known to be valid. When sending, `false` asks for it to be computed |
| `if_idx`, `sub_if_idx` | The interface |
| `vlan`, `vlan_tci` | The outer VLAN tag the packet carried, also at the NETWORK layers |
| `flow` | FLOW and SOCKET events: process ID, endpoint IDs, local and remote address and port, protocol |
| `reflect` | REFLECT events: the other handle's process, layer, flags, priority and opening time |
| `context` | Opaque: what the backend needs to reinject a captured packet unchanged |

To send a packet back, use the address it was received with: its direction, interface and
`context` decide where it goes. To inject a new packet, start from `Address::new(layer)` and set
the direction and the interface; with an empty `context`, the backend routes it.

`Address::meta()` gives the metadata a filter sees, so `Filter::matches` can check a received
packet against another filter.

## Capabilities

The platforms differ; macOS, for example, cannot modify a packet in place. `avulse::capabilities()`
says, per layer, whether handles can be opened, divert, drop, inject and modify. `Handle::open`
refuses what the backend says it cannot do, with `Error::Unsupported`.

## On Linux

The Linux backend runs eBPF programs on the traffic-control (TC) hooks of each interface. Opening
a handle needs `CAP_BPF` and `CAP_NET_ADMIN`, or root; without them it fails with an `Error::Io`
of kind `PermissionDenied`. Kernel 5.10 or later with BTF is supported (tested on 5.15 and 6.8).

- **Filters run in the kernel** when the code generator supports them; the others take every
  packet of the layer to user space, which keeps the matching ones. Until sending exists, such
  handles must use `SNIFF`. Today that includes every filter with metadata fields, such as
  `outbound` or `iface`.
- **Interfaces.** A handle captures on the interfaces it was given (all of them by default) as
  they are when it opens. Only Ethernet and loopback devices are supported; tun and WireGuard
  devices are skipped, or refused when named. Loopback traffic is seen once, as outbound.
- **VLAN tags.** When the network card takes the outer tag off (VLAN offload), the backend puts it
  back where it was: in the frame at the `Ethernet` layer, and in `vlan`/`vlan_tci` at every
  layer.
- **Priorities** become TC priorities: `30001 - priority` (lower runs first). Priority 0 takes the
  next TC priority after every open handle.
- **Packet marks.** Packets a handle sends will carry `0x4156____` in `skb->mark` (the low 16 bits
  are the TC priority), and inbound ones redirected through `lo` carry `0x4157____`. Do not use
  these values for your own marks; ebpfdivert's `0x4D49____` marks are ignored.
- **When a process dies** without closing its handles, their programs stay attached but pass
  every packet within 3 seconds (a heartbeat stops). The next `Handle::open` removes them, and so
  does `avulse cleanup` (or `avulse::cleanup()`). Open handles are listed in a registry pinned at
  `/sys/fs/bpf/avulse/`.
