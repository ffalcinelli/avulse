# Evaluator limits

The evaluator does not allocate, so that it can run in a kernel. Every intermediate value lives in
a fixed buffer, and a filter that could exceed one is a compile error with a hint, never a wrong
answer. Wireshark has no such limits; the `LIMITS` table of the `tshark` test pins each case.

- **32 computed bytes.** A multi-range slice or a `&` on two byte strings must produce at most 32
  bytes, so every range needs a bounded length: `tcp.payload[0:2,-3:]`, not `[0:2,1:]`. A
  single-range slice is read in place and has no limit.

  ```filter,error
  tcp.payload[0:2,1:] == 00
  ```

  ```filter
  tcp.payload[0:2,-3:] == 00:01:02:03:04
  ```

- **4 occurrences.** Arithmetic and `&` combine every pair of occurrences, into at most 4 values.
  `tcp.port + tcp.port` has 4 combinations and is fine; adding a third `tcp.port` is not.

  ```filter,error
  tcp.port + tcp.port + tcp.port == 3
  ```

  ```filter
  tcp.srcport + tcp.dstport + tcp.srcport == 3
  ```

- **Fields with many occurrences.** A field is read with at most 4 occurrences. The fields with
  several occurrences (`ip.addr`, `tcp.port`, `vlan.id`, …) have at most two.

These limits may be lifted when the bytecode interpreter lands, by reading joined ranges in place.
