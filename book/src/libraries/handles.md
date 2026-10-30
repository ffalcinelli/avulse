# Handles and addresses

> **Preview.** Linux and Windows have backends for every layer: the packet layers (`Network`,
> `NetworkForward` and `Ethernet`) and the event layers (`Flow`, `Socket` and `Reflect`). macOS
> sniffs and sends at `Network` and `Ethernet` without the system extension, and supports the
> packet and event layers with it (`Avulse.app`, awaiting Developer ID signing). Elsewhere,
> `Handle::open` returns `Error::Unsupported`. The API is experimental (0.0.x) and may still
> change.

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
| `flow` | FLOW and SOCKET events: process ID and name (`flow.process_name()`), endpoint IDs, local and remote address and port, protocol |
| `reflect` | REFLECT events: the other handle's process, layer, flags, priority, opening time and filter syntax |
| `context` | Opaque: what the backend needs to reinject a captured packet unchanged |

To send a packet back, use the address it was received with: its direction, interface and
`context` decide where it goes. To inject a new packet, start from `Address::new(layer)` and set
the direction and the interface; with an empty `context`, the backend routes it.

Sending follows WinDivert's rules:

- **Checksums.** The IPv4 header, TCP and UDP checksums whose flag is `false` are computed;
  `Address::new` clears them all. ICMP and ICMPv6 checksums are sent as they are: after changing
  such a packet, call `avulse::proto::checksum::recalculate`.
- **Impostors.** A packet sent with `impostor` set loses one hop of TTL (IPv4) or hop limit
  (IPv6), and `send` fails with an `Error::Io` of kind `HostUnreachable` when none is left. Two
  handles that keep reinjecting each other's packets cannot loop forever.

`Address::meta()` gives the metadata a filter sees, so `Filter::matches` can check a received
packet against another filter. Only `iface` is missing: the address has the interface's index,
not its name. At the `Reflect` layer, `layer` and `priority` are those of the handle the event is
about.

## Statistics

`Handle::stats()` returns the handle's counters: what it diverted, sniffed or dropped, and what it
let through or lost, and why. That covers a full buffer to the handle, an owner that stopped
answering, a packet too large to divert, a packet the kernel could not copy, and a full receive
queue. On Linux the kernel keeps most of them, per handle.

## Capabilities

The platforms differ; macOS, for example, cannot modify a packet in place. `avulse::capabilities()`
says, per layer, whether handles can be opened, divert, drop, inject and modify. `Handle::open`
refuses what the backend says it cannot do, with `Error::Unsupported`. [Platforms](platforms.md)
has the matrix.

## On Windows

Windows is in progress (Phase 5). At the NETWORK layers, handles divert, sniff, drop and send
packets through the avulse driver's WFP callouts. Filters with `matches` are not supported there
yet. `Handle::open` installs and starts
the driver from `avulse.sys`, next to the executable or at `AVULSE_DRIVER`, unless
`Flags::NO_INSTALL` is set; that needs Administrator rights. Loopback packets are seen once,
outbound, as in WinDivert. `capabilities()` says what works.

- **The `Ethernet` layer** needs the driver installed as an NDIS lightweight filter, bound to the
  Ethernet adapters, once, as Administrator: `netcfg -l avulse.inf -c s -i avulse` (and
  `netcfg -u avulse` to remove it). `Handle::open` never does this itself, because binding a
  filter restarts every adapter. Until it is installed, `capabilities()` leaves the layer out
  and opening a handle there fails with `Error::Unsupported`. Handles see every frame of their
  adapters, non-IP included. Sending needs `if_idx`: the frame goes out of that adapter, or in
  through it.
- **What the card does.** A VLAN tag the network card inserts or removes (802.1Q offload) is
  put back into the frame, and into `vlan`/`vlan_tci`. A frame sent back on the same adapter
  with its `context` gets its tag taken out again. Large TCP sends (LSO), which the card
  segments, are captured whole and sent back as large sends; other frames must fit the
  adapter's MTU.
- **The `Flow`, `Socket` and `Reflect` layers** come from WFP's application layers and the
  driver's own handle table, and the filter runs in the driver.
  - A `Socket` handle without `SNIFF` refuses binds, connects, listens and accepts. The
    application's call fails with `WSAEACCES`, which is `PermissionDenied`.
  - A listening socket's close is not reported: Windows reports the closure of connected
    sockets only.
  - A `Flow` handle reports the end of the flows it saw established, at most 16,384 at a time.
- **Impostors** are tracked per layer. A packet that a `Network` handle sends is not an
  impostor at the `Ethernet` layer, and the other way round. On Linux, both layers share the TC
  hooks and their marks.
- **Out of memory**, the driver fails open. A packet or event it cannot copy goes on, and
  `Stats::load_errors` counts it.
- **Machines.** The driver builds for x64 and ARM64. It is tested on x64 only, under Driver
  Verifier with its code integrity checks (what memory integrity, HVCI, requires). No ARM64
  machine has run it yet.

## On macOS

macOS is in progress (Phase 6). Handles need root, and work in one of two ways:

- **With the avulse system extension.** `Avulse.app` installs it (`Avulse install`, from
  `/Applications`, then the user approves it). Its packet filter serves the `Network` layer, and
  the `Ethernet` layer if the system hands it frames. There, handles divert, drop, sniff and
  send.
  - A diverted packet is held by the system until its handle sends it back. Sent back
    unchanged, it goes on to lower-priority handles, then out. Sent back modified, the original
    is dropped and the new packet is injected as described below. Never sent back, it is
    dropped after 10 seconds.
  - Handles that the injected packet's sender outranks see it with `impostor` set.
  - Its flow filter gives the `Flow` layer (flows established and deleted, with their process),
    the `Socket` layer (connects, accepts and closes; a handle without `SNIFF` refuses the
    connects and accepts its filter matches; binds and listens are not seen), and `Reflect`
    (the handles the extension serves).

  The extension needs a Developer ID signature to run, so this part is untested on real
  traffic so far.
- **Without it.** The backend captures through `/dev/bpf` and runs the filter in user space.
  So, at the `Network` and `Ethernet` layers, handles **sniff** (open them with `Flags::SNIFF`)
  and **send**. Opening a diverting or dropping handle, or one at the other layers, fails with
  `Error::Unsupported`. The rest of this section is about this mode.

`capabilities()` says which mode serves each layer. `AVULSE_NO_EXTENSION=1` keeps a process on
bpf.

- **Interfaces.** By default, a handle captures every interface that is up and running and has
  an address that is not link-local, plus `lo0`. `OpenOptions::interfaces` names others. The
  `Ethernet` layer takes Ethernet interfaces only: `lo0` and `utun` have no link-layer header.
  Interfaces that appear after the handle opens are not captured.
- **Direction and loopback.** Each interface has a bpf device per direction, so `outbound` is
  exact. Loopback packets are seen once, outbound, as in WinDivert.
- **Fragments.** bpf sees packets before reassembly, so a handle never gets a reassembled
  packet. With `Flags::FRAGMENTS`, inbound fragments are delivered; without it, they are not.
- **Sending.**

  | Packet | How it is sent |
  | --- | --- |
  | IPv4, either direction | A raw socket. An inbound packet is delivered from the interface that owns its destination. |
  | IPv6, outbound | Out of the interface it was captured on, behind the Ethernet header saved in its `context`. IPv6 packets the application built, or captured on `lo0`, cannot go out. |
  | IPv6, inbound | A `utun` device that the handle creates: the stack sees it arrive from that device, not from `if_idx`. |
  | `Ethernet` frames, outbound | Out of `if_idx`, as they are. |
  | `Ethernet` frames, inbound | Only frames that carry IP, which go in as at the `Network` layer. |

  The rest fails with `Error::Unsupported`: bpf cannot inject inbound, and macOS has no
  `IPV6_HDRINCL`.
- **Impostors and loops.** A handle does not capture back what it sent itself. Other handles
  see those packets as ordinary ones (`impostor` is never set), and priorities do not order the
  handles.
- **Statistics.** `sniffed` counts the packets queued, `ring_full` the packets bpf dropped
  because a device's buffer was full, and `queue_drops` the receive queue's losses.

## On Linux

The Linux backend runs eBPF programs on the traffic-control (TC) hooks of each interface. Opening
a handle needs `CAP_BPF` and `CAP_NET_ADMIN`, or root; without them it fails with an `Error::Io`
of kind `PermissionDenied`. Kernel 5.10 or later with BTF is supported (tested on 5.15 and 6.8).

- **Filters run in the kernel** (see [Where filters run](#where-filters-run) below).
- **Sending** needs `CAP_NET_RAW` as well. Loopback packets, and new packets with an empty
  `context`, go through a raw IP socket and are routed like local traffic. A packet received
  outbound (or forwarded) goes back out of the interface it was captured on, behind the Ethernet
  header it had (with none on a device that has none, such as tun); an inbound one goes to that interface's ingress through `lo`, where the handles'
  programs redirect it. Change `if_idx` and the saved header no longer applies: an outbound
  packet is then routed, and an inbound one gets an Ethernet header to the interface's address.
  At the `Ethernet` layer, frames go out of `if_idx` as they are, or in through `lo`; `if_idx`
  must be set. A packet larger than the interface's MTU, such as the large TCP segments the stack
  hands to the network card (GSO), is segmented by the kernel. A `SEND_ONLY` handle still loads
  programs, on `lo`'s ingress only, for inbound injection.
- **Interfaces.** A handle captures on the interfaces it was given (all of them by default) as
  they are when it opens. Ethernet and loopback devices are supported at every layer. Devices
  without a link-layer header, whose packets start at the IP header (tun, WireGuard, PPP, and the
  ipip, ip6tnl and sit tunnels), are supported at the `Network` and `NetworkForward` layers only:
  they carry no frames, so the `Ethernet` layer skips them, or refuses them when named. Other
  devices, GRE tunnels among them, are skipped, or refused when named. (A GRE device without a
  remote address builds the outer header before the TC hooks see the packet, and nothing tells
  the two modes apart.) Loopback traffic is seen once, as outbound.
- **VLAN tags.** When the network card takes the outer tag off (VLAN offload), the backend puts it
  back where it was, with its TPID (0x8100, or 0x88a8 for an 802.1ad tag): in the frame at the
  `Ethernet` layer, and in `vlan`/`vlan_tci` at every layer. Frames go out and in with their tags
  in the frame, whatever the offload setting.
- **The `Ethernet` layer** sees every frame on the selected interfaces, ARP, LLDP and tagged ones
  included, from the destination MAC address on (`Link::Ethernet`). Sending puts a frame out of
  `if_idx` as it is, or in through `lo`, non-IP frames too.
- **Priorities** become TC priorities: `30001 - priority` (lower runs first). Priority 0 takes the
  next TC priority after every open handle.
- **Packet marks.** Packets a handle sends carry `0x4156____` in `skb->mark` (the low 16 bits are
  its TC priority): handles at the same or a higher priority skip them, and lower ones see
  impostors. Inbound ones on their way through `lo` carry `0x4157____`, with `0x4158____` in
  `skb->priority`. Do not use these values for your own marks; ebpfdivert's `0x4D49____` marks
  are ignored.
- **When a process dies** without closing its handles, their programs stay attached but pass
  every packet within 3 seconds (a heartbeat stops). The next `Handle::open` removes them, and so
  does `avulse cleanup` (or `avulse::cleanup()`). Open handles are listed in a registry pinned at
  `/sys/fs/bpf/avulse/`.
- **The `Flow` layer** reports TCP and UDP flows of every process (cgroup v2 must be mounted).
  - A TCP flow is established when its handshake completes, and deleted when it closes.
    `outbound` says that this host opened it.
  - A UDP flow is established by the first datagram a socket sends to, or receives from, an
    address and port. It is deleted when the socket closes.
  - The events have no packet, so filters test `event`, `outbound`, `local.*`, `remote.*`,
    `protocol`, `process.pid`, `process.name` and `endpoint.id`. `ip`, `tcp` and the other
    protocol fields are false, as in WinDivert.
  - `parent_endpoint_id` is always 0.
  - The process is the one that made the socket. It is 0 for sockets made before the handle
    opened, and for sockets accepted from such a listener.
- **The `Socket` layer** reports bind, connect, listen, accept and close for the sockets of
  every process. It has the same fields as `Flow`. For a connect, the local endpoint is known
  only if the socket was bound before.
  - With `SNIFF`, the handle only reports.
  - Without it, the handle refuses the binds and connects its filter matches: the call fails
    with `EPERM`, and the event is reported. With `DROP`, the call is refused and nothing is
    reported.
  - Linux cannot refuse a listen or an accept. A filter that can match one fails to open
    (`Error::Unsupported`) unless it has `SNIFF`. `event in {bind connect}`, or a test of
    `event`, keeps those events out.
  - The kernel decides each call, so the filter must compile exactly to eBPF. It can test
    `event`, `local.*`, `remote.*`, `protocol`, `process.pid`, `inbound`, `outbound` and
    `loopback`, with comparisons, sets, arithmetic and the handle's constants. It can also test
    `process.name` with `==`, `!=` and sets. A test of a packet field, such as `tcp`, is
    false. Anything else fails to open without `SNIFF`: `contains`, ordering and `upper()`
    on `process.name`, `endpoint.id`, `timestamp` and `random*`.
- **The process name** is the `comm` of the thread that made the socket, at most 15 bytes,
  which threads can change. A name that is not UTF-8 is absent in user space, but the kernel
  compares its bytes.
- **The `Reflect` layer** reports the handles of every process, as the registry lists them,
  every 100 ms.
  - At first, it reports every open handle, itself included, as `ReflectOpen`.
  - Then it reports a handle when it opens, and `ReflectClose` when it closes or its owner dies.
  - The data is the handle's filter as it was written, and `Address::reflect.syntax` says in
    which language (`Syntax::Native` or `Syntax::WinDivert`). `Address::reflect` also has its
    process, layer, flags, priority and opening time.
  - Processes in another PID namespace, or that use another bpffs, are not seen.

### Where filters run

The backend compiles the filter to eBPF when the handle opens, and the kernel decides each packet
on its own: no trip to user space for the packets the filter does not match. That covers the
header fields of Ethernet, VLAN tags, ARP, IPv4, IPv6, TCP (with the MSS, window scale, SACK
permitted and timestamps options), UDP and ICMP; quantifiers, sets (searched as a tree, whatever
their size), address prefixes and ranges; comparisons and slices of bytes, and `contains` in
headers; `len()`, `count()`, arithmetic and `&` on numbers, and comparisons of two fields; and the
metadata: `inbound`/`outbound`, `loopback`, `impostor`, `fragment`, `ifidx`, `iface` (by name,
resolved when the handle opens: an interface renamed later is not seen under its new name),
`protocol`, `local.*`/`remote.*`, and `layer`, `event` and `priority`.

What the kernel cannot run is widened: each such test becomes the presence of the protocols it
reads (`icmp.seq == 1` becomes `icmp`, since a test of an absent field is false), or `true` when
it reads none (`false` under a `not`), so that the kernel takes a superset of the packets the
filter matches, and user space runs the whole filter on them. It keeps the matching ones and sends the others back at once; with `DROP`,
it drops the matching ones. Among what is widened: `contains` and `matches` on payloads and
frames, layer operators (`vlan.id#2`), `@field`, `&` on bytes, slices of several ranges, string
functions, `timestamp` and `random*`, and the ICMP identifier fields. `avulse filter
explain` prints what the kernel runs:

```console
$ avulse filter explain 'tcp.dstport == 80 and tcp.payload contains "GET"'
(and (any_eq tcp.dstport 80) (contains tcp.payload 47:45:54))
linux kernel: the superset `tcp.dstport == 80`, and user space filters what it takes (the eBPF generator does not support `contains` on bytes that may be longer than 64)
```

At the `Ethernet` layer, a frame whose outer VLAN tag the card took off is seen without it by the
kernel, and the filter as if it were in place: `vlan.*`, `ieee8021ad.*`, `eth.type` and
`frame.len` count it. A filter that reads link-layer bytes (`frame`, `eth`, or the tags' bytes,
`vlan` and `ieee8021ad`, compared or sliced) takes such frames to user space, which decides with
the tag back in place.
