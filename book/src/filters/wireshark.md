# Differences from Wireshark

A test compares Avulse with `tshark` 4.6+ on every supported field and on a table of about 300
filters (`AVULSE_TSHARK=1 cargo test -p avulse-filter tshark`, run in CI). A filter that Wireshark
accepts and Avulse compiles selects the same packets, except in the cases below. Each one is
pinned by a row in that test.

## Different results

- **Outermost headers only.** Wireshark also dissects the datagram that an ICMP error quotes, so
  there `udp.port == 53` matches a "port unreachable" about DNS traffic. Avulse, like WinDivert,
  reads only the outer headers.
- **No partial headers.** Wireshark keeps the fields of a header that is cut short, as far as the
  bytes go. Avulse drops the incomplete header, so its fields are absent.
- **No reassembly.** As in Wireshark with reassembly off, `tcp.len` is absent on IP fragments.
- **One TCP option of each kind.** A header with two MSS options has two `tcp.options.mss_val`
  values in Wireshark; Avulse reads the first. Normal packets carry each option once.
- **Signed arithmetic throughout.** `tcp.srcport + -1` subtracts one; Wireshark converts the `-1`
  to the field's unsigned type. Avulse also accepts literals beyond the field's range in
  arithmetic (`tcp.srcport + 1 == 65536`), which Wireshark rejects.
- **Rust regular expressions, not PCRE2.** Look-around and backreferences are rejected, and `$`
  matches only at the very end, where PCRE2 also matches before a final newline (write `\n?$`).

## Filters Avulse rejects

- **Stricter types.** A literal that cannot fit the field is an error (`ip.flags == 8`), where
  Wireshark accepts the filter and never matches.
- **Fixed evaluation buffers.** Filters whose values could exceed the evaluator's buffers are
  compile errors. See [evaluator limits](limits.md).
- **Stateful and application fields.** `tcp.seq`, `tcp.stream`, `tcp.analysis.*`, `http.*`,
  `dns.*` and the others in the [field reference](../reference/fields.md#rejected-wireshark-fields)
  need state across packets or a dissector. Each is rejected with a hint.
- **Repeated TCP options.** `tcp.option_kind`, `tcp.option_len`, `tcp.options.nop` and
  `tcp.options.eol` repeat once per option, up to 40 times, more than a value can hold; test an
  option (`tcp.options.sack_perm`) or search `tcp.options` instead. SACK edges are relative
  sequence numbers, which need stream tracking.
- **Formatting functions.** `string()`, `dec()`, `hex()`, `float()` and `vals()`, and `${field}`
  references to the packet selected in the GUI.

## Extensions Wireshark rejects

Avulse also accepts some syntax that Wireshark rejects. It never changes the meaning of a
Wireshark filter:

- `#`, `//` and `/* */` comments;
- `let` macros, used as `$name`;
- `~=`, Wireshark 3.6's spelling of `!==`;
- space-separated sets (`{80 443}`);
- the [metadata fields](metadata.md);
- symbolic names Wireshark does not know (`syn`, `echo-request`, `ip.proto == tcp`, where
  Wireshark reads `tcp` as the protocol field).

## Version notes

The reference is Wireshark 4.6 and later. Older versions, such as Wireshark 4.2, differ on byte literals
(`tcp[13] == 18`), on `len(ipv6)` of non-first fragments and on upper-case keywords. Value labels
are merged from Wireshark 4.6 and 4.7, which renamed many `ip.proto` labels.
