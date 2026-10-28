# WinDivert compatibility

`libavulse_windivert` runs programs written for WinDivert on avulse. It is the
`avulse-windivert-compat` crate, built as a shared library. On Linux it exports the C API of
[libebpfdivert](https://github.com/ffalcinelli/ebpfdivert), which is WinDivert 2.2's API with
Linux conventions:

- the `ebpfdivert_open`, `_recv`, `_send`, … calls (`include/ebpfdivert.h` in ebpfdivert);
- negative `errno` values for errors;
- WinDivert's 80-byte `WINDIVERT_ADDRESS`;
- WinDivert's filter language, layers, flags, parameters and helpers.

[pydivert](https://github.com/ffalcinelli/pydivert) and
[jdivert](https://github.com/ffalcinelli/jdivert) use libebpfdivert as their Linux backend, so
they can load this library in its place, unchanged. Both test suites pass against it: pydivert's
on Python, and jdivert's through JNA (Java 8) and Panama (Java 22 and later). The Windows exports (a drop-in `WinDivert.dll`)
come with the Windows driver.

```console
$ cargo build --release -p avulse-windivert-compat
$ PYDIVERT_EBPFDIVERT_LIB=$PWD/target/release/libavulse_windivert.so python3 app.py
$ mvn test -Debpfdivert.skipDownload=true -Debpfdivert.local=$PWD/target/release/libavulse_windivert.so
```

## What it maps to

| WinDivert | avulse |
| --- | --- |
| A filter string | [WinDivert filters](../filters/windivert.md), compiled by avulse's own front-end, with WinDivert's semantics |
| `WINDIVERT_ADDRESS` | [`Address`](handles.md#the-address), field by field. The 64-byte union holds the layer's data as WinDivert lays it out. At the NETWORK layers, its last 56 bytes hold avulse's reinjection context, so send a packet back with the address it came with |
| `WinDivertHelperCalcChecksums`, `HashPacket`, `EvalFilter` | Reimplemented with WinDivert's packet parser. They give WinDivert's results byte for byte, `random8/16/32` included |
| `WinDivertHelperFormatFilter` | The filter in a canonical WinDivert syntax (`Filter::format_windivert`) |
| REFLECT's data | WinDivert's serialized filter object (`@WinDiv_…`, with its NUL), compiled from the other handle's filter as WinDivert's compiler does (`Filter::windivert_object`) |
| `ebpfdivert_get_handle_stats` | `Handle::stats` |
| `ebpfdivert_unregister` | `avulse::cleanup` |

## Differences from libebpfdivert

- **REFLECT data of native filters.** A handle opened with a native filter has no WinDivert
  object. Its REFLECT events carry the filter's text instead (`udp.dstport == 53`).
- **Formatted filters.** `format_filter` returns a canonical form of the filter as written.
  WinDivert decompiles its filter object instead, which can look different, after its
  simplifications. Both compile to the same filter.
- **Lost in the address.** WinDivert's address has no room for the VLAN tag or the process name,
  which avulse's has.
- **Filter errors.** `compile_filter` reports avulse's message and position, not WinDivert's
  fixed error strings.
- **Ignored options.** `ring_bytes` is accepted and ignored: avulse sizes its own buffers.
  `set_print` is accepted, and its callback is never called: avulse does not log.
- **Malformed TCP headers.** On a TCP header whose data offset runs past the end of the packet,
  `calc_checksums` checksums the bytes that are there. WinDivert reads past the end.
- **Events with a packet.** At FLOW and SOCKET, `eval_filter` accepts a non-NULL packet pointer
  when its length is 0. WinDivert requires NULL.
