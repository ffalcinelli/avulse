# avulse

Divert, modify and re-inject network packets on Linux, Windows and macOS. Avulse covers every WinDivert
feature, adds an Ethernet layer, and uses a Wireshark-compatible filter language.

**Pre-alpha.** This crate holds the handle API: handles, flags, parameters and the packet address.
On Linux, handles divert, sniff, drop and send packets at the NETWORK, NETWORK_FORWARD and ETHERNET
layers. Other platforms have no backend yet: opening a handle there fails with
`Error::Unsupported`. Follow the project at
<https://github.com/ffalcinelli/avulse>, and see the
[roadmap](https://github.com/ffalcinelli/avulse/blob/main/docs/roadmap.md).

```rust,no_run
use avulse::{Flags, Handle, Layer, MAX_PACKET_LEN};

// Divert outbound HTTP, and send it on unchanged.
let handle = Handle::open("outbound and tcp.dstport == 80", Layer::Network, 0, Flags::NONE)?;
let mut buf = vec![0; MAX_PACKET_LEN];
loop {
    let (len, addr) = handle.recv(&mut buf)?;
    handle.send(&buf[..len], &addr)?;
}
# Ok::<(), avulse::Error>(())
```
