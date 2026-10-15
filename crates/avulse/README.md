# avulse

Divert, modify and re-inject network packets on Linux, Windows and macOS. Avulse covers every WinDivert
feature, adds an Ethernet layer, and uses a Wireshark-compatible filter language.

**Pre-alpha.** This crate holds the API that the platform backends will implement: handles, flags,
parameters and the packet address. No platform has a backend yet, so opening a handle fails with
`Error::Unsupported`; the Linux backend is next. Follow the project at
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
