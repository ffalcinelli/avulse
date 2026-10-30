# Platforms

What each backend does, layer by layer. `avulse::capabilities()` reports the same thing at run
time for the machine you are on: a handle opened for something it cannot do fails with
`Error::Unsupported`. The details of each platform are in
[Handles and addresses](handles.md).

macOS has two modes. **With the extension**, the avulse system extension (`Avulse.app install`)
serves the handles. Its packet filter holds the packets it diverts, and its flow filter reports
sockets. **Without it**, the backend copies packets through `/dev/bpf`, so handles can only
sniff and send.

## Packet layers

| | Linux | Windows | macOS, with the extension | macOS, without it |
| --- | --- | --- | --- | --- |
| `Network` | divert, sniff, drop, send, modify | divert, sniff, drop, send, modify | divert, sniff, drop, send; a modified packet replaces the original | sniff, send |
| `NetworkForward` | divert, sniff, drop, send, modify | divert, sniff, drop, send, modify | no | no |
| `Ethernet` | divert, sniff, drop, send, modify; every frame, non-IP included | the same, once the NDIS filter is installed (`netcfg`) | as `Network`, if the system hands the filter frames | sniff, send; inbound only frames that carry IP |

## Event layers

| | Linux | Windows | macOS, with the extension | macOS, without it |
| --- | --- | --- | --- | --- |
| `Flow` | established, deleted | established, deleted | established, deleted | no |
| `Socket` | bind, connect, listen, accept, close; refuses binds and connects | bind, connect, listen, accept, close; refuses all four calls | connect, accept, close; refuses connects and accepts; binds and listens are not seen | no |
| `Reflect` | every handle on the machine | every handle on the machine | the extension's handles | no |

## Across layers

| | Linux | Windows | macOS, with the extension | macOS, without it |
| --- | --- | --- | --- | --- |
| Rights | root | Administrator | root | root |
| What it needs | kernel 5.10+ with BTF; cgroup v2 for `Flow` and `Socket` | the avulse driver, signed (test signing until it is) | the system extension, signed with a Developer ID and approved by the user | nothing |
| Where filters run | in the kernel (eBPF), else partly in user space | in the driver (bytecode) | in the extension (user space) | in the process |
| Priorities and impostors | yes | yes | yes | no: every handle sees every packet |
| Loopback | seen as sent and received | seen once, outbound | seen once, outbound | seen once, outbound |
| When the process dies | its handles fail open within 3 s | its handles close | its handles close, and what they held goes on | nothing is held |

## Status

- **Linux** (Phases 2 to 4) and **Windows** (Phase 5) are complete and tested, Windows under
  Driver Verifier.
- **macOS** without the extension is tested on GitHub's macOS runners.
- **macOS** with the extension: its logic is tested on any platform, and its XPC service on the
  runners, without the filters. The filters need a Developer ID signature to run, so they have
  not met real traffic yet.
- Release signing (the Windows driver's attestation, the macOS Developer ID and notarization)
  comes with the first release.
