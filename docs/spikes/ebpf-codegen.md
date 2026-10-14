# Spike A: eBPF code generation

**Verdict: go.** A filter's IR can be compiled to eBPF at runtime and run exactly in the kernel.
The verifier of Linux 5.15 and 6.8 accepted every generated program. The kernel's verdicts agreed
with the IR evaluator on every frame.

Date: 2026-10-14. Code: `crates/ebpf`. Kernels: Ubuntu 24.04 (6.8.0-86) and Ubuntu 22.04
(5.15.0-160), in the Vagrant VMs of `Vagrantfile`.

## What was built

The spike went further than the planned `tcp.dstport == N`, so that the numbers mean something.

- **`bpf/tc.bpf.c`** is a static cls_bpf program in C. It parses Ethernet, two VLAN tags, ARP,
  IPv4, IPv6 with up to 8 extension headers and fragments, TCP, UDP, ICMP and ICMPv6. It applies
  `avulse_proto::Packet`'s rules: a header cut short is absent, padding is trimmed, and a
  non-first fragment has no transport header.
  - It writes the result to a per-CPU **facts** map: offsets, presence bits and the payload
    range, 32 bytes laid out in `bpf/facts.h`.
  - It then tail-calls the matcher.
  - Header bytes are read with `bpf_skb_load_bytes`, so paged skbs work.
- **`codegen`** compiles the IR to the matcher, through a small assembler (`insn`) that has
  forward labels only.
  - **Supported:**
    - `and`, `or`, `not`, `xor`, and WinDivert's conditional;
    - presence tests;
    - comparisons and set membership, with ranges and CIDR, on every fixed field of Ethernet,
      IPv4, IPv6, TCP, UDP, ICMP and ICMPv6, including the two-valued `ip.addr`, `tcp.port` and
      `udp.port` under `any` and `all`;
    - `==` and `!=` on header and payload bytes and on single slices of them.
  - **Unsupported,** so `compile` returns `Error::Unsupported` (the backend's cue to filter in
    user space):
    - `contains`, `matches`, arithmetic, `len` and `count`;
    - layers, `@field`, IPv6 addresses, VLAN and option fields, metadata fields.
- **`loader`** (Linux) loads the object with `aya`, and the matcher with the `bpf()` system call.
  It runs both through `BPF_PROG_TEST_RUN`.
- **Tests.**
  - `tests/emu.rs` runs every generated matcher in a small eBPF interpreter, on the facts that
    `Facts::from_packet` derives from `avulse-proto`. It compares the result with
    `Filter::matches`. It runs in `cargo test` on every platform, and catches all 15 bugs planted
    in the generator.
  - `tests/kernel.rs` (root only, `AVULSE_BPF=1`) checks three things in the kernel:
    - the C parser leaves the same facts as `Facts::from_packet`;
    - the verifier accepts every matcher;
    - the verdicts agree with the evaluator.

## Results

| | 6.8 | 5.15 |
| --- | --- | --- |
| Facts equal to `Facts::from_packet` (well-formed, padded, truncated and mutated frames) | 3,340 of 3,340 | 3,340 of 3,340 |
| Matchers accepted by the verifier (139 single-feature filters and 300 random combinations) | 439 of 439 | 439 of 439 |
| Verdicts equal to `Filter::matches` | 1,466,260 of 1,466,260 | 1,466,260 of 1,466,260 |
| Most verifier work among those (instructions processed) | 1,245 | 7,459 |
| 2,000-port set: 8,043 instructions, processed | 12,060 | 12,060 |
| 300-term `or`: 9,619 instructions, processed | 17,703 | 25,180 |
| 1,000-byte comparison: 792 instructions, processed | 835 | 835 |

Time per packet, from `BPF_PROG_TEST_RUN` (average of 200,000 runs in a VirtualBox VM). The test
frame is TCP to port 443, carrying `GET / HTTP/1.1`:

| | 6.8 | 5.15 |
| --- | --- | --- |
| Parse only (no matcher) | 85 ns | 169 ns |
| `tcp.dstport == 443` | 104 ns | 202 ns |
| `ip.src == 10.0.0.0/8 and tcp.dstport in {80 443} and tcp.payload[0:4] == "GET "` | 118 ns | 259 ns |
| `tcp.port in {1 … 2000}` (match at 443) | 1,522 ns | 1,704 ns |

## Findings that change the design

1. **A tail call does not return.** The roadmap said the matcher "returns the verdict", which is
   wrong. The chain has three programs instead:
   - the static parser tail-calls the matcher (slot 0);
   - the matcher writes the verdict into the facts and tail-calls the static action program
     (slot 1);
   - the action program diverts or passes. When a slot is empty, the packet passes (fail-open).

   That is two tail calls per packet. The alternative was `freplace` (`BPF_PROG_TYPE_EXT`) of a
   global function: a real call and return, but it needs BTF for the generated code. Two tail
   calls are cheap enough that `freplace` is not worth it.
2. **The verifier rejects unreachable instructions.** A constant subtest, such as `frame`, leaves
   dead code behind. The assembler now drops every instruction that no path reaches.
   `emu::check_shape` checks the rules the verifier enforces before it runs anything: forward
   jumps, reachability, and no path that runs off the end.
3. **`aya` covers only part of what we need.**
   - It loads the clang-built object on 5.15 and handles the BTF and maps. Clang 23 builds the
     object on the host.
   - It needs the section name `classifier`, not `tc`.
   - It has no public API for three things we need, so `loader.rs` makes about 150 lines of raw
     `bpf()` calls:
     - loading raw instructions;
     - putting a program fd it did not load into a `ProgramArray`;
     - `BPF_PROG_TEST_RUN`.

   This is acceptable. Upstreaming a raw-load API to aya is an option.
4. **Set membership needs a better lowering.** Sets compile to linear scans, so a 2,000-port set
   costs 1.5 µs per packet. Phase 2 options:
   - sorted ranges, searched by a binary decision tree of jumps;
   - above a few dozen items, a `BPF_MAP_TYPE_HASH` or `LPM_TRIE` lookup.
5. **`xor` doubles code.** Each `xor` compiles its right operand twice, so 12 nested `xor`s exceed
   the size limit. The fix is to keep each operand's result in a register or a stack slot.
6. **The size limit is 32,767 instructions**, because jump offsets are 16 bits. The 32-bit
   `gotol` needs 6.4 or later. A larger matcher must fall back to user space, or be split into
   several programs chained by tail calls. Verifier work stays far below its limit of 1,000,000:
   the 300-term `or` processed at most 25,180 instructions. The 5.15 verifier explores up to 6
   times more instructions than 6.8, so test the largest programs on 5.15.
7. **Reading fields with `bpf_skb_load_bytes`** costs one helper call per field. It is robust,
   and the timings above are fine. If profiling says otherwise, the parser could copy the first
   bytes of the L3 and L4 headers into the facts, so that the matcher reads them from the map.
8. `JMP32` instructions (Linux 5.1 and later) keep 32-bit comparisons short. They are well inside
   the 5.10 baseline.
9. The test binary built on the host runs unchanged in both VMs: glibc 2.39 is a weak requirement,
   which 22.04 tolerates. The privileged tests therefore need nothing installed in the VMs.

## Left for Phase 2

- **VLAN offload.** On a real TC hook, the outer VLAN tag is usually in `skb->vlan_tci`, not in
  the packet data. `BPF_PROG_TEST_RUN` keeps it in the data. The parser must account for both, as
  must the restore on capture.
- **Fields and layers.**
  - The NETWORK layers (the buffer starts at the IP header).
  - Metadata fields such as direction, interface and mark, in the facts.
  - IPv6 addresses (16-byte comparisons, as for bytes), `eth.addr`, VLAN fields and TCP options.
  - `contains` and arithmetic.
- **Attaching on clsact** and diverting in the action program, then the superset fallback for
  refused or oversized filters.
- An arm64 run.

## Test environment note

On this workstation (Linux 7.2 host, VirtualBox 7.2.20), the Ubuntu 24.04 box hung at boot with
guest RCU stalls 2 times out of 4. Destroying it and running `vagrant up` again worked; the 22.04
box booted every time.
